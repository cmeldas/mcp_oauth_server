# -*- coding: utf-8 -*-
from odoo import fields, models

# Scope API klíčů pro přímý přístup z Claude Code (bez OAuth): Předvolby → Zabezpečení účtu →
# Nový API klíč. Klíč s jiným scope (běžné RPC) do MCP nepustí.
APIKEY_SCOPE_READ = "mcp"
APIKEY_SCOPE_WRITE = "mcp_write"


class ResUsersApikeysDescription(models.TransientModel):
    _inherit = "res.users.apikeys.description"

    scope = fields.Selection(
        selection_add=[(APIKEY_SCOPE_READ, "MCP – read only"), (APIKEY_SCOPE_WRITE, "MCP – read and write")],
        ondelete={APIKEY_SCOPE_READ: "cascade", APIKEY_SCOPE_WRITE: "cascade"},
    )
