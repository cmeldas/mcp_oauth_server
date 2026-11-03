# -*- coding: utf-8 -*-
import json
from datetime import timedelta

from odoo import api, fields, models

ARGUMENTS_LIMIT = 4000
VALUE_LIMIT = 300


def shorten(env, value):
    """Argumenty do auditu bez dlouhých textů (base64 obrázků a podobně)."""
    if isinstance(value, str):
        if len(value) <= VALUE_LIMIT:
            return value
        return value[:VALUE_LIMIT] + "… " + env._("(%s characters)", len(value))
    if isinstance(value, dict):
        return {key: shorten(env, item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [shorten(env, item) for item in value[:50]]
    return value


class McpAuditLog(models.Model):
    _name = "mcp.audit.log"
    _description = "MCP Call Audit"
    _order = "id desc"
    _rec_name = "tool"

    user_id = fields.Many2one("res.users", string="User", readonly=True, index=True, ondelete="set null")
    grant_id = fields.Many2one("mcp.oauth.grant", string="Connection", readonly=True, ondelete="set null")
    client_name = fields.Char(string="Client", readonly=True)
    auth = fields.Selection([("oauth", "OAuth"), ("apikey", "API Key")], string="Authentication", readonly=True)
    tool = fields.Char(string="Tool", readonly=True, index=True)
    model = fields.Char(string="Model", readonly=True)
    res_ids = fields.Char(string="Record IDs", readonly=True)
    arguments = fields.Text(string="Arguments", readonly=True)
    preview = fields.Boolean(string="Preview", readonly=True)
    status = fields.Selection(
        [("ok", "OK"), ("denied", "Denied"), ("error", "Error")], string="Result", readonly=True, index=True,
    )
    message = fields.Text(string="Message", readonly=True)
    duration_ms = fields.Integer(string="Duration (ms)", readonly=True)
    ip = fields.Char(string="IP", readonly=True)

    @api.model
    def _record(self, ctx, ip: str | None, tool: str, arguments, status: str, message: str | None, duration_ms: int):
        args = arguments if isinstance(arguments, dict) else {}
        ids = args.get("ids") or args.get("id")
        self.sudo().create({
            "user_id": ctx.env.uid,
            "grant_id": ctx.grant_id,
            "client_name": ctx.client_name,
            "auth": ctx.auth,
            "tool": tool,
            "model": args.get("model") if isinstance(args.get("model"), str) else False,
            "res_ids": json.dumps(ids)[:500] if ids else False,
            "arguments": json.dumps(shorten(ctx.env, args), ensure_ascii=False, default=str)[:ARGUMENTS_LIMIT],
            "preview": bool(args.get("preview")),
            "status": status,
            "message": (message or "")[:4000] or False,
            "duration_ms": duration_ms,
            "ip": ip,
        })

    @api.autovacuum
    def _gc_old_logs(self):
        days = self.env["ir.config_parameter"].sudo().get_int("mcp_oauth_server.audit_days", 90) or 90
        self.sudo().search([("create_date", "<", fields.Datetime.now() - timedelta(days=days))]).unlink()
