# -*- coding: utf-8 -*-
from odoo import api, fields, models

from ..lib.i18n import localize
from ..lib.tools import all_tools


class McpTool(models.Model):
    """Nástroje MCP v Odoo: zapnout, vypnout, omezit na skupiny a uživatele.

    Jiné addony přidávají vlastní nástroje děděním a metodou `_mcp_extra_tools()`:

        class McpTool(models.Model):
            _inherit = "mcp.tool"

            @api.model
            def _mcp_extra_tools(self):
                return super()._mcp_extra_tools() + [Tool("helpdesk_summary", …)]
    """
    _name = "mcp.tool"
    _description = "MCP Tool"
    _order = "sequence, id"

    name = fields.Char(string="Tool", required=True, readonly=True)
    # název a popis jsou v kódu nástroje, v jazyce uživatele (překlady addonu, který nástroj přidal)
    title = fields.Char(string="Title", compute="_compute_from_code")
    description = fields.Text(string="Description", compute="_compute_from_code")
    kind = fields.Selection(
        [("read", "Read"), ("draft", "Draft to Send"), ("write", "Write"), ("admin", "MCP Administration")],
        string="Kind", readonly=True,
    )
    module = fields.Char(string="From Module", readonly=True)
    available = fields.Boolean(string="Available", compute="_compute_from_code",
                               help="The tool exists in the code. After uninstalling the addon that added it, the "
                                    "record stays with its settings, but the AI does not see the tool.")
    sequence = fields.Integer(readonly=True)
    enabled = fields.Boolean(string="Enabled", default=True,
                             help="The AI client does not see a disabled tool at all.")
    group_ids = fields.Many2many(
        "res.groups", "mcp_tool_group_rel", "tool_id", "group_id", string="Only for Groups",
        help="Empty together with Only for Users = everyone. Otherwise being in one of the groups or among "
             "the users is enough.",
    )
    user_ids = fields.Many2many(
        "res.users", "mcp_tool_user_rel", "tool_id", "user_id", string="Only for Users",
        domain=[("share", "=", False)],
    )
    note = fields.Char(string="Note")

    _name_unique = models.Constraint("unique(name)", "The tool is already in the list.")

    @api.model
    def _mcp_extra_tools(self) -> list:
        """Háček pro jiné addony: vraťte `super()._mcp_extra_tools() + [Tool(...)]`. Viz README, Vlastní nástroje."""
        return []

    @api.depends_context("lang")
    def _compute_from_code(self):
        tools = {tool.name: tool for tool in all_tools(self.env)}
        for record in self:
            tool = tools.get(record.name)
            record.available = bool(tool)
            record.title = localize(self.env, tool.title) if tool else False
            record.description = localize(self.env, tool.description) if tool else False

    def init(self):
        """Doplnit záznamy nástrojů z kódu. Běží při instalaci a aktualizaci tohohle modulu i každého addonu,
        který `mcp.tool` dědí, takže se objeví i jeho nástroje. Nastavení oprávnění se nepřepisuje."""
        Tool = self.sudo().with_context(active_test=False)
        existing = {tool.name: tool for tool in Tool.search([])}
        for index, tool in enumerate(all_tools(self.env)):
            values = {"kind": tool.tool_kind, "module": tool.module, "sequence": index * 10}
            if tool.name in existing:
                existing[tool.name].write(values)
                continue
            groups = [self.env.ref(xmlid, raise_if_not_found=False) for xmlid in tool.default_groups]
            Tool.create({**values, "name": tool.name, "group_ids": [(6, 0, [g.id for g in groups if g])]})

    @api.model
    def _denied_names(self, user) -> frozenset[str]:
        """Nástroje, které uživatel nesmí: vypnuté, nebo omezené na jiné lidi a skupiny.

        Rozhodují skutečné skupiny uživatele (i administrátorské): jde o to, kdo smí nástroj používat,
        ne o přístup k datům.
        """
        user_groups = set(user.sudo().all_group_ids.ids)
        denied = set()
        for tool in self.sudo().search([]):
            if not tool.enabled:
                denied.add(tool.name)
            elif (tool.group_ids or tool.user_ids) and user not in tool.user_ids \
                    and not user_groups & set(tool.group_ids.ids):
                denied.add(tool.name)
        return frozenset(denied)
