# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import ValidationError

INSTRUCTIONS_LIMIT = 8000


class ResCompany(models.Model):
    _inherit = "res.company"

    mcp_system_name = fields.Char(
        string="System Name for AI",
        help="How this Odoo introduces itself to the AI client, e.g. \"Odoo My Company\". Helps when the client "
             "has several Odoo instances connected (each as its own connector).",
    )
    mcp_about = fields.Text(
        string="What Is This Odoo",
        help="A few sentences for the AI: whose system it is, what it is used for, what it will find in it "
             "and what not.",
    )
    mcp_instructions = fields.Text(
        string="Rules for AI",
        help="Company rules the AI has to follow when reading and writing. It gets them right when connecting "
             "and again in the whoami tool.",
    )

    @api.constrains("mcp_about", "mcp_instructions")
    def _check_mcp_instructions_length(self):
        for company in self:
            if len(company.mcp_about or "") + len(company.mcp_instructions or "") > INSTRUCTIONS_LIMIT:
                raise ValidationError(self.env._(
                    "AI instructions can have at most %s characters in total. A longer text needlessly "
                    "overloads the AI client.",
                    INSTRUCTIONS_LIMIT))

    def _mcp_system_name(self) -> str:
        self.ensure_one()
        return (self.mcp_system_name or "").strip() or f"Odoo {self.name}"

    @api.model
    def _mcp_instructions_action(self):
        """Menu Pokyny pro AI: formulář firmy uživatele jen s poli MCP (název okna v jeho jazyce)."""
        return {
            "type": "ir.actions.act_window",
            "name": self.env._("AI Instructions"),
            "res_model": "res.company",
            "res_id": self.env.company.id,
            "view_mode": "form",
            "views": [[self.env.ref("mcp_oauth_server.res_company_view_form_mcp").id, "form"]],
            "target": "current",
        }
