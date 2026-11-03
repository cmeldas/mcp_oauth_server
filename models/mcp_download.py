# -*- coding: utf-8 -*-
import base64
from datetime import timedelta

from odoo import api, fields, models

from ..lib import oauth

DOWNLOAD_TTL = timedelta(minutes=15)


class McpDownload(models.Model):
    _name = "mcp.download"
    _description = "File Download via MCP"
    _order = "id desc"
    _rec_name = "filename"

    token_hash = fields.Char(required=True, index=True, readonly=True)
    user_id = fields.Many2one("res.users", string="User", required=True, ondelete="cascade", readonly=True)
    report_id = fields.Many2one("ir.actions.report", string="Report", ondelete="set null", readonly=True)
    filename = fields.Char(string="File", required=True, readonly=True)
    mimetype = fields.Char(readonly=True)
    data = fields.Binary(attachment=True, readonly=True)
    size = fields.Integer(string="Size (B)", readonly=True)
    expires = fields.Datetime(string="Valid Until", required=True, readonly=True)
    download_count = fields.Integer(string="Downloads", readonly=True)

    def _key(self) -> str:
        return self.env["ir.config_parameter"].sudo().get_str("database.secret")

    @api.model
    def _create_download(self, user, filename: str, content: bytes, mimetype: str, report=None) -> dict:
        token = oauth.new_token(oauth.DOWNLOAD_PREFIX)
        expires = fields.Datetime.now() + DOWNLOAD_TTL
        self.sudo().create({
            "token_hash": oauth.token_hash(self._key(), token),
            "user_id": user.id,
            "report_id": report.id if report else False,
            "filename": filename,
            "mimetype": mimetype,
            "data": base64.b64encode(content).decode(),
            "size": len(content),
            "expires": expires,
        })
        return {"token": token, "expires": expires}

    @api.model
    def _find_valid(self, token: str):
        if not token or not token.startswith(oauth.DOWNLOAD_PREFIX):
            return self.browse()
        return self.sudo().search([
            ("token_hash", "=", oauth.token_hash(self._key(), token)),
            ("expires", ">", fields.Datetime.now()),
        ], limit=1)

    @api.autovacuum
    def _gc_expired(self):
        self.sudo().search([("expires", "<", fields.Datetime.now())]).unlink()
