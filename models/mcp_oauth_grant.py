# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import AccessError

from odoo.tools.translate import LazyTranslate

from ..lib import oauth

_lt = LazyTranslate(__name__)

ACCESS_TTL = timedelta(hours=1)
REFRESH_TTL = timedelta(days=30)
CODE_TTL = timedelta(minutes=2)
# Claude obnovuje token i souběžně; stejný refresh token v téhle lhůtě není útok.
REFRESH_REUSE_GRACE = timedelta(seconds=60)
TOUCH_INTERVAL = timedelta(minutes=5)


def secret_key(env) -> str:
    return env["ir.config_parameter"].sudo().get_str("database.secret")


class McpOauthGrant(models.Model):
    _name = "mcp.oauth.grant"
    _description = "AI Client Connection via MCP"
    _order = "last_used desc, id desc"
    _rec_name = "client_name"

    user_id = fields.Many2one("res.users", string="User", required=True, ondelete="cascade", index=True, readonly=True)
    client_id = fields.Many2one("mcp.oauth.client", string="Client", required=True, ondelete="cascade", readonly=True)
    client_name = fields.Char(related="client_id.name", string="Application")
    scope = fields.Char(string="Scope", readonly=True)
    write_allowed = fields.Boolean(string="Write", compute="_compute_write_allowed")
    resource = fields.Char(string="MCP URL", readonly=True)
    redirect_host = fields.Char(string="Redirects To", readonly=True)
    active = fields.Boolean(default=True, readonly=True)
    last_used = fields.Datetime(string="Last Used", readonly=True)
    last_ip = fields.Char(string="Last IP", readonly=True)
    revoked_date = fields.Datetime(string="Revoked On", readonly=True)
    token_ids = fields.One2many("mcp.oauth.token", "grant_id")

    @api.depends("scope")
    def _compute_write_allowed(self):
        for grant in self:
            grant.write_allowed = oauth.SCOPE_WRITE in (grant.scope or "").split()

    def action_revoke(self):
        if not self.env.is_system() and any(grant.user_id != self.env.user for grant in self):
            raise AccessError(self.env._("You can only revoke your own connections."))
        self.sudo()._revoke()
        return True

    def _revoke(self):
        self.token_ids.unlink()
        self.write({"active": False, "revoked_date": fields.Datetime.now()})

    def _scopes(self) -> frozenset[str]:
        self.ensure_one()
        return frozenset((self.scope or "").split())

    def _issue_tokens(self) -> dict:
        """Nový access a refresh token pro spojení (odpověď token endpointu, RFC 6749 kap. 5.1)."""
        self.ensure_one()
        key = secret_key(self.env)
        now = fields.Datetime.now()
        access = oauth.new_token(oauth.ACCESS_PREFIX)
        refresh = oauth.new_token(oauth.REFRESH_PREFIX)
        self.env["mcp.oauth.token"].sudo().create([
            {"grant_id": self.id, "kind": "access", "token_hash": oauth.token_hash(key, access), "expires": now + ACCESS_TTL},
            {"grant_id": self.id, "kind": "refresh", "token_hash": oauth.token_hash(key, refresh), "expires": now + REFRESH_TTL},
        ])
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(ACCESS_TTL.total_seconds()),
            "refresh_token": refresh,
            "scope": self.scope,
        }

    @api.model
    def _refresh(self, refresh_token: str, client, resource: str | None) -> dict:
        """Obnova tokenu s rotací. Starý refresh token použitý znovu po lhůtě odvolá celé spojení."""
        token = self.env["mcp.oauth.token"]._find(refresh_token, "refresh")
        if not token:
            raise oauth.OAuthError("invalid_grant", _lt("The refresh token is invalid."))
        grant = token.grant_id
        if grant.client_id != client:
            raise oauth.OAuthError("invalid_grant", _lt("The refresh token belongs to another client."))
        if resource and resource.rstrip("/") != grant.resource:
            raise oauth.OAuthError("invalid_target", _lt("The token is for another MCP URL."))
        now = fields.Datetime.now()
        if token.used_date:
            if token.used_date < now - REFRESH_REUSE_GRACE:
                grant._revoke()
                raise oauth.OAuthError("invalid_grant", _lt("The refresh token was already used, the connection is revoked."))
        elif token.expires < now:
            raise oauth.OAuthError("invalid_grant", _lt("The refresh token has expired."))
        if not grant.active or not grant.user_id.active or not grant.client_id.active:
            raise oauth.OAuthError("invalid_grant", _lt("The connection is revoked."))
        if not token.used_date:
            token.used_date = now
        return grant._issue_tokens()

    def _touch(self, ip: str | None):
        """Poznamenat poslední použití, nejvýš jednou za pět minut (zápis je v samostatné transakci)."""
        now = fields.Datetime.now()
        stale = self.filtered(lambda g: not g.last_used or g.last_used < now - TOUCH_INTERVAL or g.last_ip != ip)
        if stale:
            stale.write({"last_used": now, "last_ip": ip})

    @api.autovacuum
    def _gc_tokens(self):
        now = fields.Datetime.now()
        Token = self.env["mcp.oauth.token"].sudo()
        Token.search([("kind", "=", "access"), ("expires", "<", now - timedelta(days=1))]).unlink()
        Token.search([("kind", "=", "refresh"), "|", ("expires", "<", now),
                      ("used_date", "<", now - timedelta(days=1))]).unlink()
        self.env["mcp.oauth.code"].sudo().search([("expires", "<", now)]).unlink()
        idle = self.sudo().search([("token_ids", "=", False), ("active", "=", True)])
        idle.write({"active": False, "revoked_date": now})


class McpOauthToken(models.Model):
    _name = "mcp.oauth.token"
    _description = "MCP Token"

    grant_id = fields.Many2one("mcp.oauth.grant", required=True, ondelete="cascade", index=True)
    kind = fields.Selection([("access", "Access"), ("refresh", "Refresh")], required=True)
    token_hash = fields.Char(required=True, index=True)
    expires = fields.Datetime(required=True)
    used_date = fields.Datetime()

    _token_hash_unique = models.Constraint("unique(token_hash)", "The token already exists.")

    @api.model
    def _find(self, token: str | None, kind: str):
        if not token:
            return self.browse()
        return self.sudo().search([("token_hash", "=", oauth.token_hash(secret_key(self.env), token)),
                                   ("kind", "=", kind)], limit=1)

    @api.model
    def _authenticate(self, token: str, resource: str):
        """Spojení pro platný access token vydaný pro tuhle adresu MCP, jinak prázdný záznam."""
        found = self._find(token, "access")
        grant = found.grant_id
        if (not found or found.expires < fields.Datetime.now() or not grant.active or not grant.client_id.active
                or grant.resource != resource or not grant.user_id.active or not grant.user_id._is_internal()):
            return self.env["mcp.oauth.grant"]
        return grant


class McpOauthCode(models.Model):
    _name = "mcp.oauth.code"
    _description = "MCP Authorization Code"

    code_hash = fields.Char(required=True, index=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    client_id = fields.Many2one("mcp.oauth.client", required=True, ondelete="cascade")
    redirect_uri = fields.Char(required=True)
    code_challenge = fields.Char(required=True)
    scope = fields.Char()
    resource = fields.Char(required=True)
    expires = fields.Datetime(required=True)

    @api.model
    def _issue(self, user, client, redirect_uri: str, code_challenge: str, scope: str, resource: str) -> str:
        code = oauth.new_token(oauth.CODE_PREFIX)
        self.sudo().create({
            "code_hash": oauth.token_hash(secret_key(self.env), code),
            "user_id": user.id,
            "client_id": client.id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "scope": scope,
            "resource": resource,
            "expires": fields.Datetime.now() + CODE_TTL,
        })
        return code

    @api.model
    def _exchange(self, code: str, client, redirect_uri: str, verifier: str, resource: str | None) -> dict:
        """Kód + PKCE → spojení a tokeny. Kód jde použít jen jednou."""
        found = self.sudo().search([("code_hash", "=", oauth.token_hash(secret_key(self.env), code or ""))], limit=1)
        if not found:
            raise oauth.OAuthError("invalid_grant", _lt("The authorization code is invalid or already used."))
        values = {
            "user": found.user_id, "client": found.client_id, "redirect_uri": found.redirect_uri,
            "challenge": found.code_challenge, "scope": found.scope, "resource": found.resource,
            "expires": found.expires,
        }
        found.unlink()
        if values["expires"] < fields.Datetime.now():
            raise oauth.OAuthError("invalid_grant", _lt("The authorization code has expired."))
        if values["client"] != client:
            raise oauth.OAuthError("invalid_grant", _lt("The authorization code belongs to another client."))
        if redirect_uri != values["redirect_uri"]:
            raise oauth.OAuthError("invalid_grant", _lt("redirect_uri does not match the authorization."))
        if resource and resource.rstrip("/") != values["resource"]:
            raise oauth.OAuthError("invalid_target", _lt("resource does not match the authorization."))
        if not oauth.pkce_matches(verifier, values["challenge"]):
            raise oauth.OAuthError("invalid_grant", _lt("code_verifier does not match code_challenge (PKCE)."))
        grant = self.env["mcp.oauth.grant"].sudo().create({
            "user_id": values["user"].id,
            "client_id": client.id,
            "scope": values["scope"],
            "resource": values["resource"],
            "redirect_host": oauth.host_of(redirect_uri),
        })
        return grant._issue_tokens()
