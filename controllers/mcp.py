# -*- coding: utf-8 -*-
"""Endpoint MCP `/api/mcp` (Streamable HTTP, bezstavový, odpovědi JSON bez SSE)."""
import logging

from odoo import http
from odoo.http import request

from ..lib import oauth, protocol
from ..lib.policy import McpContext
from ..lib.tools import tools_by_name
from ..models.res_users_apikeys import APIKEY_SCOPE_READ, APIKEY_SCOPE_WRITE
from .common import (MCP_PATH, base_url, client_ip, cors_headers, json_response, origin_allowed,
                     resource_metadata_url, resource_url)

_logger = logging.getLogger(__name__)


def module_version() -> str:
    module = request.env["ir.module.module"].sudo().search([("name", "=", "mcp_oauth_server")], limit=1)
    return module.latest_version or ""


def config_flag(key: str, default: str = "1") -> bool:
    value = request.env["ir.config_parameter"].sudo().get_str(f"mcp_oauth_server.{key}", default)
    return value not in ("0", "False", "false", "")


class McpController(http.Controller):

    # Čtecí nástroje běží v savepointu, který se vždy vrátí zpět; audit a poslední použití
    # spojení se zapisují do téže transakce, proto route čte i zapisuje (readonly=False).
    @http.route(MCP_PATH, type="http", auth="none", methods=["GET", "POST", "DELETE", "OPTIONS"],
                csrf=False, save_session=False, readonly=False)
    def mcp(self, **_kwargs):
        httprequest = request.httprequest
        origin = httprequest.headers.get("Origin")
        cors = cors_headers(origin)
        if not origin_allowed(origin):
            return json_response({"error": "Origin is not allowed."}, status=403)
        if httprequest.method == "OPTIONS":
            return request.make_response("", headers=cors, status=204)
        if httprequest.method != "POST":
            # bez SSE streamu a bez session: GET i DELETE odmítnout (MCP Streamable HTTP to dovoluje)
            return request.make_response("", headers=[("Allow", "POST, OPTIONS"), *cors], status=405)

        ctx = self._authenticate()
        if ctx is None:
            error = "invalid_token" if oauth.bearer_token(httprequest.headers.get("Authorization")) else None
            # hlavičky HTTP jsou latin-1, popis chyby proto anglicky
            headers = [("WWW-Authenticate", oauth.www_authenticate(
                resource_metadata_url(), scope=f"{oauth.SCOPE_READ} {oauth.SCOPE_WRITE}", error=error,
                description="The access token is missing, expired or invalid." if error else None)), *cors]
            return json_response({"error": error or "unauthorized"}, status=401, headers=headers)

        try:
            messages, batch = protocol.parse_body(httprequest.get_data(cache=True))
        except ValueError:
            return json_response(protocol.error(None, protocol.PARSE_ERROR, "Parse error"), status=400, headers=cors)

        version = module_version()
        audit = self._auditor(ctx)
        responses = [r for r in (protocol.handle_message(ctx, m, audit, version) for m in messages) if r is not None]
        self._touch(ctx)
        if not responses:
            return request.make_response("", headers=cors, status=202)
        return json_response(responses if batch else responses[0], headers=cors)

    def _authenticate(self) -> McpContext | None:
        """Access token z OAuth (`mcpa_…`), nebo API klíč se scope MCP (Claude Code bez OAuth)."""
        token = oauth.bearer_token(request.httprequest.headers.get("Authorization"))
        if not token:
            return None
        env = request.env
        grant = None
        if token.startswith(oauth.ACCESS_PREFIX):
            grant = env["mcp.oauth.token"].sudo()._authenticate(token, resource_url())
            if not grant:
                return None
            user, scopes, auth, client_name = grant.user_id, grant._scopes(), "oauth", grant.client_id.name
        else:
            if not config_flag("allow_api_keys"):
                return None
            keys = env["res.users.apikeys"].sudo()
            scopes = frozenset({oauth.SCOPE_READ, oauth.SCOPE_WRITE})
            uid = keys._check_credentials(scope=APIKEY_SCOPE_WRITE, key=token)
            if not uid:
                scopes = frozenset({oauth.SCOPE_READ})
                uid = keys._check_credentials(scope=APIKEY_SCOPE_READ, key=token)
            if not uid:
                return None
            user = env["res.users"].sudo().browse(uid)
            if not user._is_internal():
                return None
            auth, client_name = "apikey", None
        request.update_env(user=user.id)
        # mcp_request: pravidla MCP přes MCP jen navrhnout, nikdy schválit ani změnit (viz mcp.rule)
        # hlavní firma uživatele první: podle ní se řídí pokyny pro AI a výchozí firma záznamů
        companies = [user.company_id.id] + [cid for cid in user.company_ids.ids if cid != user.company_id.id]
        context = {**request.env["res.users"].context_get(), "allowed_company_ids": companies, "mcp_request": True}
        request.update_context(**context)
        # jazyk uživatele z context_get(): podle něj se překládají popisy nástrojů i hlášky
        client_name = client_name or request.env._("API key")
        return McpContext(env=request.env, base_url=base_url(), scopes=frozenset(scopes), auth=auth,
                          client_name=client_name, grant_id=grant.id if grant else None,
                          yolo=bool(user.sudo().mcp_yolo))

    def _auditor(self, ctx: McpContext):
        log_reads = config_flag("log_reads")
        ip = client_ip()
        Log = request.env["mcp.audit.log"].sudo()

        def audit(tool, arguments, status, message, duration_ms):
            known = tools_by_name(ctx).get(tool)
            if status == "ok" and known and known.readonly and not log_reads:
                return
            try:
                with request.env.cr.savepoint():
                    Log._record(ctx, ip, tool, arguments, status, message, duration_ms)
            except Exception:  # noqa: BLE001 – audit nesmí shodit odpověď nástroje
                _logger.exception("Writing the MCP audit log failed")
        return audit

    def _touch(self, ctx: McpContext):
        if not ctx.grant_id:
            return
        try:
            with request.env.cr.savepoint():
                request.env["mcp.oauth.grant"].sudo().browse(ctx.grant_id)._touch(client_ip())
        except Exception:  # noqa: BLE001
            _logger.warning("Could not record the last use of the MCP connection", exc_info=True)
