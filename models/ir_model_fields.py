# -*- coding: utf-8 -*-
from odoo import fields, models


class IrModelFields(models.Model):
    _inherit = "ir.model.fields"

    mcp_hidden = fields.Boolean(
        string="Hidden from MCP",
        help="The AI client does not see the field via MCP and cannot use it in a filter. Passwords, tokens and "
             "keys are always hidden.",
    )

    def _get_writable_properties(self):
        # příznak jde zapnout i u polí ze standardních modulů (ostatní vlastnosti mění jen kód)
        return [*super()._get_writable_properties(), "mcp_hidden"]
