# -*- coding: utf-8 -*-
from odoo import fields, models


class ResUsers(models.Model):
    _inherit = "res.users"

    mcp_grant_ids = fields.One2many("mcp.oauth.grant", "user_id", string="Connected Apps (MCP)")
    mcp_yolo = fields.Boolean(
        string="MCP: Full Access (YOLO)", groups="base.group_system", copy=False,
        help="AI clients of this user work via MCP with all the user's Odoo rights, administrator rights and "
             "technical models included, without write rules. Writing still needs a connection that allows "
             "it. Passwords, tokens and keys stay hidden; the MCP settings can only be changed in Odoo. Meant "
             "for test databases.",
    )

    def write(self, vals):
        result = super().write(vals)
        if "password" in vals or vals.get("active") is False:
            # nové heslo nebo deaktivace uživatele = konec všech připojení AI klientů
            self.env["mcp.oauth.grant"].sudo().search([("user_id", "in", self.ids)])._revoke()
        return result
