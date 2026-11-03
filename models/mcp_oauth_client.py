# -*- coding: utf-8 -*-
import hmac
import json
import secrets
from datetime import timedelta

from odoo import api, fields, models

from odoo.tools.translate import LazyTranslate

from ..lib import oauth

_lt = LazyTranslate(__name__)

CIMD_REFRESH = timedelta(hours=24)
DEFAULT_CIMD_HOSTS = "claude.ai, claude.com, chatgpt.com"
DEFAULT_REDIRECT_URIS = "\n".join((
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/*",
))


def config_list(value: str) -> list[str]:
    return [item.strip() for item in (value or "").replace(",", "\n").splitlines() if item.strip()]


class McpOauthClient(models.Model):
    _name = "mcp.oauth.client"
    _description = "MCP OAuth Client"
    _order = "id desc"

    name = fields.Char(string="Name", required=True)
    client_id = fields.Char(string="Client ID", required=True, readonly=True, index=True)
    kind = fields.Selection(
        [("cimd", "Client Metadata Document (CIMD)"), ("dcr", "Dynamic Client Registration (DCR)")],
        string="Registration", required=True, readonly=True,
    )
    redirect_uris = fields.Text(string="Redirect URIs", readonly=True, help="JSON list")
    client_secret_hash = fields.Char(readonly=True, copy=False)
    auth_method = fields.Char(string="Token Endpoint Authentication", readonly=True, default="none")
    metadata = fields.Text(string="Client Metadata", readonly=True)
    fetched_date = fields.Datetime(string="Metadata Fetched On", readonly=True)
    active = fields.Boolean(default=True, help="A blocked client cannot connect and its connections stop working.")
    grant_ids = fields.One2many("mcp.oauth.grant", "client_id", string="Connections")
    grant_count = fields.Integer(string="Number of Connections", compute="_compute_grant_count")

    _client_id_unique = models.Constraint("unique(client_id)", "A client with this Client ID already exists.")

    def _compute_grant_count(self):
        for client in self:
            client.grant_count = len(client.grant_ids)

    def _redirect_uri_list(self) -> list[str]:
        self.ensure_one()
        try:
            return [u for u in json.loads(self.redirect_uris or "[]") if isinstance(u, str)]
        except ValueError:
            return []

    def _config(self, key: str, default: str = "") -> str:
        return self.env["ir.config_parameter"].sudo().get_str(f"mcp_oauth_server.{key}", default)

    def _dcr_enabled(self) -> bool:
        return self._config("allow_dcr", "1") not in ("0", "False", "false", "")

    def _cimd_hosts(self) -> list[str]:
        return config_list(self._config("cimd_hosts", DEFAULT_CIMD_HOSTS))

    def _redirect_patterns(self) -> list[str]:
        return config_list(self._config("redirect_uris", DEFAULT_REDIRECT_URIS))

    @api.model
    def _resolve_client(self, client_id: str):
        """Klient pro autorizaci: z CIMD (stáhne nebo obnoví popis) nebo zaregistrovaný přes DCR."""
        if not client_id:
            raise oauth.OAuthError("invalid_request", _lt("client_id is missing."))
        Client = self.sudo().with_context(active_test=False)
        client = Client.search([("client_id", "=", client_id)], limit=1)
        if oauth.is_cimd_client_id(client_id):
            if not oauth.host_allowed(oauth.host_of(client_id), self._cimd_hosts()):
                raise oauth.OAuthError("invalid_client", _lt("Clients from %s are not allowed.", oauth.host_of(client_id)))
            if not client or not client.fetched_date or client.fetched_date < fields.Datetime.now() - CIMD_REFRESH:
                metadata = oauth.fetch_client_metadata(client_id)
                values = {
                    "name": str(metadata.get("client_name") or oauth.host_of(client_id))[:100],
                    "redirect_uris": json.dumps(metadata["redirect_uris"]),
                    "metadata": json.dumps(metadata, ensure_ascii=False),
                    "fetched_date": fields.Datetime.now(),
                }
                if client:
                    client.write(values)
                else:
                    client = Client.create({**values, "client_id": client_id, "kind": "cimd"})
        if not client:
            raise oauth.OAuthError("invalid_client", _lt("Unknown client. Register it again."), status=401)
        if not client.active:
            raise oauth.OAuthError("invalid_client", _lt("The client is blocked in Odoo."), status=401)
        return client

    @api.model
    def _register_client(self, payload: dict) -> dict:
        """Dynamic Client Registration (RFC 7591). Vrátí odpověď pro klienta."""
        if not self._dcr_enabled():
            raise oauth.OAuthError("invalid_request", _lt("Dynamic client registration is disabled in Odoo."))
        if not isinstance(payload, dict):
            raise oauth.OAuthError("invalid_client_metadata", _lt("The body must be a JSON object."))
        redirect_uris = payload.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris):
            raise oauth.OAuthError("invalid_redirect_uri", _lt("redirect_uris is missing."))
        patterns = self._redirect_patterns()
        refused = [u for u in redirect_uris if not oauth.redirect_allowed(u, patterns)]
        if refused:
            raise oauth.OAuthError("invalid_redirect_uri", _lt("The redirect URI %s is not allowed.", refused[0]))
        grant_types = payload.get("grant_types") or ["authorization_code", "refresh_token"]
        if not set(grant_types) <= {"authorization_code", "refresh_token"}:
            raise oauth.OAuthError("invalid_client_metadata",
                                   _lt("Supported grant_types: authorization_code, refresh_token."))
        method = payload.get("token_endpoint_auth_method") or "client_secret_basic"
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            method = "none"
        client_id = "mcp-" + secrets.token_urlsafe(16)
        secret = oauth.new_token("mcps_") if method != "none" else None
        name = str(payload.get("client_name") or oauth.host_of(redirect_uris[0]) or "MCP client")[:100]
        self.sudo().create({
            "name": name,
            "client_id": client_id,
            "kind": "dcr",
            "redirect_uris": json.dumps(redirect_uris),
            "auth_method": method,
            "client_secret_hash": oauth.token_hash(self._secret_key(), secret) if secret else False,
            "metadata": json.dumps(payload, ensure_ascii=False)[:20000],
        })
        result = {
            "client_id": client_id,
            "client_id_issued_at": int(fields.Datetime.now().timestamp()),
            "client_name": name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if secret:
            result.update(client_secret=secret, client_secret_expires_at=0)
        return result

    def _check_client_secret(self, secret: str | None) -> bool:
        self.ensure_one()
        if not self.client_secret_hash:
            return True  # veřejný klient, chrání ho PKCE
        if not secret:
            return False
        return hmac.compare_digest(self.client_secret_hash, oauth.token_hash(self._secret_key(), secret))

    def _secret_key(self) -> str:
        return self.env["ir.config_parameter"].sudo().get_str("database.secret")

    def _display_host(self, redirect_uri: str) -> str:
        return oauth.host_of(redirect_uri) or redirect_uri

    @api.autovacuum
    def _gc_unused_dcr_clients(self):
        """DCR registruje klienta při každém novém připojení; nepoužité po týdnu smazat."""
        limit = fields.Datetime.now() - timedelta(days=7)
        self.sudo().with_context(active_test=False).search([
            ("kind", "=", "dcr"), ("create_date", "<", limit), ("grant_ids", "=", False),
        ]).unlink()
