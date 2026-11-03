# -*- coding: utf-8 -*-
from odoo import fields, models


class ResUsers(models.Model):
    _inherit = "res.users"

    mcp_grant_ids = fields.One2many("mcp.oauth.grant", "user_id", string="Connected Apps (MCP)")

    def write(self, vals):
        result = super().write(vals)
        if "password" in vals or vals.get("active") is False:
            # nové heslo nebo deaktivace uživatele = konec všech připojení AI klientů
            self.env["mcp.oauth.grant"].sudo().search([("user_id", "in", self.ids)])._revoke()
        return result
