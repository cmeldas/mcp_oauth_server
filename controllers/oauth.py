# -*- coding: utf-8 -*-
"""OAuth 2.1 server pro MCP: metadata (RFC 9728, RFC 8414), autorizace se souhlasem, tokeny, DCR."""
import json
import logging

from odoo import http
from odoo.http import request
from odoo.tools.translate import LazyTranslate

from ..lib import oauth
from ..lib.policy import OPERATION_LABELS
from .common import MCP_PATH, NO_STORE, base_url, json_response, resource_url

_logger = logging.getLogger(__name__)
_lt = LazyTranslate(__name__)

AUTH_METHODS = ["none", "client_secret_post", "client_secret_basic"]


def company_name() -> str:
    return request.env["res.company"].sudo().search([], limit=1).name or "Odoo"


class McpOAuthController(http.Controller):

    # --- metadata ------------------------------------------------------------------------------

    @http.route(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + MCP_PATH],
                type="http", auth="none", methods=["GET"], csrf=False, save_session=False, cors="*")
    def protected_resource_metadata(self, **_kwargs):
        base = base_url()
        return json_response({
            "resource": resource_url(),
            "authorization_servers": [base],
            "scopes_supported": [oauth.SCOPE_READ, oauth.SCOPE_WRITE],
            "bearer_methods_supported": ["header"],
            "resource_name": f"Odoo – {company_name()}",
            "resource_documentation": "https://github.com/cmeldas/mcp_oauth_server",
        })

    @http.route("/.well-known/oauth-authorization-server", type="http", auth="none", methods=["GET"],
                csrf=False, save_session=False, cors="*")
    def authorization_server_metadata(self, **_kwargs):
        base = base_url()
        data = {
            "issuer": base,
            "authorization_endpoint": f"{base}{MCP_PATH}/oauth/authorize",
            "token_endpoint": f"{base}{MCP_PATH}/oauth/token",
            "revocation_endpoint": f"{base}{MCP_PATH}/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": AUTH_METHODS,
            "revocation_endpoint_auth_methods_supported": AUTH_METHODS,
            "scopes_supported": list(oauth.SUPPORTED_SCOPES),
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }
        if request.env["mcp.oauth.client"]._dcr_enabled():
            data["registration_endpoint"] = f"{base}{MCP_PATH}/oauth/register"
        return json_response(data)

    # --- autorizace ----------------------------------------------------------------------------

    def _error_page(self, message: str, status: int = 400):
        """Stránka chyby pro člověka v prohlížeči, `message` už v jeho jazyce."""
        response = request.render("mcp_oauth_server.oauth_error", {"error": message})
        response.status_code = status
        return response

    def _redirect_error(self, redirect_uri: str, error: oauth.OAuthError, state: str | None):
        return request.redirect(oauth.add_query(redirect_uri, {
            "error": error.error, "error_description": error.description, "state": state, "iss": base_url(),
        }), local=False)

    def _validate_client(self, params: dict):
        """Klient a adresa přesměrování. Chyba tady se ukáže na stránce, ne přesměrováním (RFC 6749 4.1.2.1)."""
        client = request.env["mcp.oauth.client"].sudo()._resolve_client(params.get("client_id"))
        redirect_uri = params.get("redirect_uri") or ""
        if not oauth.redirect_matches(redirect_uri, client._redirect_uri_list()):
            raise oauth.OAuthError("invalid_request", _lt("The redirect URI %s is not registered for the client.",
                                                          redirect_uri or _lt("(missing)")))
        return client, redirect_uri

    def _validate_request(self, params: dict) -> dict:
        if params.get("response_type") != "code":
            raise oauth.OAuthError("unsupported_response_type", _lt("Only response_type=code is supported."))
        challenge = params.get("code_challenge")
        if not challenge or params.get("code_challenge_method") != "S256":
            raise oauth.OAuthError("invalid_request", _lt("PKCE is missing (code_challenge with method S256)."))
        resource = (params.get("resource") or resource_url()).rstrip("/")
        if resource != resource_url():
            raise oauth.OAuthError("invalid_target", _lt("This server only issues tokens for %s.", resource_url()))
        scopes = oauth.parse_scope(params.get("scope")) or [oauth.SCOPE_READ]
        return {"challenge": challenge, "resource": resource, "scopes": scopes}

    def _use_user_lang(self):
        """Souhlas a chyby v jazyce přihlášeného uživatele, stejném jako popisy nástrojů pro AI."""
        lang = request.env.user.lang
        if lang and lang != request.env.lang:
            request.update_context(lang=lang)

    # website=True: s nainstalovaným webem obaluje web.login_layout layout webu, který potřebuje `website`
    @http.route(MCP_PATH + "/oauth/authorize", type="http", auth="user", methods=["GET"], website=True, sitemap=False)
    def authorize(self, **params):
        self._use_user_lang()
        try:
            client, redirect_uri = self._validate_client(params)
        except oauth.OAuthError as error:
            return self._error_page(error.description_for(request.env))
        try:
            values = self._validate_request(params)
        except oauth.OAuthError as error:
            return self._redirect_error(redirect_uri, error, params.get("state"))
        user = request.env.user
        if not user._is_internal():
            return self._error_page(request.env._("Only an internal Odoo user can connect an AI client."),
                                    status=403)
        rules = request.env["mcp.rule"].sudo().search([]).filtered(lambda r: not r.user_ids or user in r.user_ids)
        return request.render("mcp_oauth_server.oauth_consent", {
            "client": client,
            "client_host": oauth.host_of(client.client_id) if client.kind == "cimd" else None,
            "redirect_host": oauth.host_of(redirect_uri),
            "loopback": oauth.is_loopback(redirect_uri),
            "user": user,
            "company": company_name(),
            "database": request.env.cr.dbname,
            "write_requested": oauth.SCOPE_WRITE in values["scopes"],
            "yolo": user.sudo().mcp_yolo,
            "rules": [{"name": r.name, "app": r.privilege_id.name, "models": r.model_count,
                       "operations": ", ".join(request.env._(OPERATION_LABELS[op])
                                               for op in ("create", "write", "archive", "unlink", "note")
                                               if r[f"perm_{op}"]) or request.env._("actions only")}
                      for r in rules],
            "params": {key: params.get(key) or "" for key in (
                "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge",
                "code_challenge_method", "resource")},
        })

    @http.route(MCP_PATH + "/oauth/authorize/decision", type="http", auth="user", methods=["POST"], website=True,
                sitemap=False)
    def authorize_decision(self, **params):
        self._use_user_lang()
        try:
            client, redirect_uri = self._validate_client(params)
        except oauth.OAuthError as error:
            return self._error_page(error.description_for(request.env))
        try:
            values = self._validate_request(params)
        except oauth.OAuthError as error:
            return self._redirect_error(redirect_uri, error, params.get("state"))
        user = request.env.user
        if not user._is_internal():
            return self._error_page(request.env._("Only an internal Odoo user can connect an AI client."),
                                    status=403)
        if params.get("decision") != "allow":
            return self._redirect_error(redirect_uri, oauth.OAuthError("access_denied", _lt("The user denied access.")),
                                        params.get("state"))
        scopes = [oauth.SCOPE_READ]
        if oauth.SCOPE_WRITE in values["scopes"] and params.get("allow_write"):
            scopes.append(oauth.SCOPE_WRITE)
        if oauth.SCOPE_OFFLINE in values["scopes"]:
            scopes.append(oauth.SCOPE_OFFLINE)
        code = request.env["mcp.oauth.code"].sudo()._issue(
            user, client, redirect_uri, values["challenge"], " ".join(scopes), values["resource"])
        _logger.info("MCP: user %s allowed client %s (%s)", user.login, client.name, " ".join(scopes))
        return request.redirect(oauth.add_query(redirect_uri, {
            "code": code, "state": params.get("state"), "iss": base_url(),
        }), local=False)

    # --- token, registrace, odvolání -----------------------------------------------------------

    def _form(self) -> dict:
        return dict(request.httprequest.form.items())

    def _token_client(self, form: dict):
        basic = oauth.basic_credentials(request.httprequest.headers.get("Authorization"))
        client_id = basic[0] if basic else form.get("client_id")
        secret = basic[1] if basic else form.get("client_secret")
        client = request.env["mcp.oauth.client"].sudo()._resolve_client(client_id)
        if not client._check_client_secret(secret):
            raise oauth.OAuthError("invalid_client", _lt("Invalid client credentials."), status=401)
        return client

    @http.route(MCP_PATH + "/oauth/token", type="http", auth="none", methods=["POST"], csrf=False,
                save_session=False, readonly=False, cors="*")
    def token(self, **_kwargs):
        form = self._form()
        try:
            client = self._token_client(form)
            grant_type = form.get("grant_type")
            if grant_type == "authorization_code":
                data = request.env["mcp.oauth.code"].sudo()._exchange(
                    form.get("code"), client, form.get("redirect_uri"), form.get("code_verifier"), form.get("resource"))
            elif grant_type == "refresh_token":
                data = request.env["mcp.oauth.grant"].sudo()._refresh(form.get("refresh_token"), client, form.get("resource"))
            else:
                raise oauth.OAuthError("unsupported_grant_type", _lt("Supported: authorization_code, refresh_token."))
        except oauth.OAuthError as error:
            return json_response(error.as_dict(), status=error.status, headers=NO_STORE)
        return json_response(data, headers=NO_STORE)

    @http.route(MCP_PATH + "/oauth/register", type="http", auth="none", methods=["POST"], csrf=False,
                save_session=False, readonly=False, cors="*")
    def register(self, **_kwargs):
        try:
            payload = json.loads(request.httprequest.get_data() or b"{}")
            data = request.env["mcp.oauth.client"].sudo()._register_client(payload)
        except ValueError:
            return json_response({"error": "invalid_client_metadata", "error_description": "The body is not JSON."},
                                 status=400)
        except oauth.OAuthError as error:
            return json_response(error.as_dict(), status=error.status, headers=NO_STORE)
        return json_response(data, status=201, headers=NO_STORE)

    @http.route(MCP_PATH + "/oauth/revoke", type="http", auth="none", methods=["POST"], csrf=False,
                save_session=False, readonly=False, cors="*")
    def revoke(self, **_kwargs):
        """RFC 7009: odpověď je vždy 200, i pro neznámý token."""
        form = self._form()
        token = form.get("token") or ""
        Token = request.env["mcp.oauth.token"].sudo()
        found = Token._find(token, "refresh") or Token._find(token, "access")
        if found:
            found.grant_id._revoke()
        return json_response({}, headers=NO_STORE)
