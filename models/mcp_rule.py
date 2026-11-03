# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import AccessError, ValidationError
from odoo.tools import SQL
from odoo.tools.safe_eval import safe_eval, time as safe_time
from odoo.tools.translate import LazyTranslate

_lt = LazyTranslate(__name__)

# Model patří aplikaci, pokud oprávnění (ir.access) pro skupinu té aplikace definuje stejný
# modul jako model sám. Sdílené modely (kontakty, produkty) tak patří jen své aplikaci,
# i když je jiné aplikace (Sklady, Prodej) taky smějí upravovat.
PRIVILEGE_MODELS_SQL = """
WITH model_home AS (
    SELECT DISTINCT ON (d.res_id) d.res_id AS model_id, d.module
    FROM ir_model_data d
    WHERE d.model = 'ir.model'
    ORDER BY d.res_id, d.id
)
SELECT DISTINCT m.model
FROM ir_access a
JOIN res_groups g ON g.id = a.group_id
JOIN ir_model_data ad ON ad.model = 'ir.access' AND ad.res_id = a.id
JOIN model_home h ON h.model_id = a.model_id AND h.module = ad.module
JOIN ir_model m ON m.id = a.model_id
WHERE g.privilege_id = %s AND a.active AND (a.operation LIKE '%%c%%' OR a.operation LIKE '%%u%%')
"""

# slovník, ne n-tice: extraktor překladů by z ("perm_…", _lt(…)) vzal i název pole
OPERATION_FIELDS = {
    "perm_create": _lt("create"),
    "perm_write": _lt("edit"),
    "perm_archive": _lt("archive"),
    "perm_unlink": _lt("delete"),
    "perm_note": _lt("chatter notes"),
}
# Pole, která přes MCP nejde nastavit ani při návrhu: rozhoduje o nich jen člověk v Odoo.
APPROVAL_FIELDS = frozenset({"state", "approved_by_id", "approved_date"})


class McpRule(models.Model):
    _name = "mcp.rule"
    _description = "MCP Write Rule"
    _inherit = ["mail.thread", "mail.activity.mixin"]
    _order = "state, sequence, id"

    name = fields.Char(string="Name", required=True, tracking=True)
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)
    state = fields.Selection(
        [("proposed", "AI Proposal"), ("approved", "Approved"), ("rejected", "Rejected")],
        string="Status", default="approved", required=True, tracking=True, copy=False,
        help="Only approved rules apply. An AI proposal (propose_rule tool) has to be approved by a person in Odoo.",
    )
    proposed_by_id = fields.Many2one("res.users", string="Proposed by User", readonly=True, copy=False)
    proposal_client = fields.Char(string="Proposed by Client", readonly=True, copy=False)
    proposal_reason = fields.Text(string="AI Reasoning", readonly=True, copy=False)
    approved_by_id = fields.Many2one("res.users", string="Approved by", readonly=True, copy=False, tracking=True)
    approved_date = fields.Datetime(string="Approved On", readonly=True, copy=False)
    summary = fields.Char(string="Allows", compute="_compute_summary")
    privilege_id = fields.Many2one(
        "res.groups.privilege", string="App", tracking=True,
        help="The Access Rights row from the user form (Sales, Inventory, …). The rule covers the models of that "
             "app: those the app itself creates or edits in Odoo.",
    )
    extra_model_ids = fields.Many2many(
        "ir.model", "mcp_rule_extra_model_rel", "rule_id", "model_id", string="Additional Models",
        help="Models in addition to the app, or all models when no app is selected.",
    )
    excluded_model_ids = fields.Many2many(
        "ir.model", "mcp_rule_excluded_model_rel", "rule_id", "model_id", string="Excluded Models",
    )
    model_ids = fields.Many2many("ir.model", string="Rule Models", compute="_compute_model_ids")
    model_count = fields.Integer(string="Number of Models", compute="_compute_model_ids")
    perm_create = fields.Boolean(string="Create", tracking=True)
    perm_write = fields.Boolean(string="Edit", tracking=True)
    perm_archive = fields.Boolean(string="Archive", tracking=True)
    perm_unlink = fields.Boolean(string="Delete", tracking=True,
                                 help="Deleting cannot be undone. Archiving is usually enough.")
    perm_note = fields.Boolean(string="Chatter Notes", tracking=True)
    field_ids = fields.Many2many(
        "ir.model.fields", "mcp_rule_field_rel", "rule_id", "field_id", string="Only These Fields",
        help="Empty = all fields of the rule's models except hidden, sensitive and read-only ones. If you list "
             "fields for some models only, the rule does not allow writing to the other models.",
    )
    domain = fields.Char(
        string="Only Records", tracking=True,
        help="Odoo domain, e.g. [(\"categ_id.name\", \"=\", \"Beer\")]. Applies to all models of the rule; "
             "a record has to match the condition before and after writing. Empty = all records.",
    )
    action_names = fields.Char(
        string="Allowed Actions", tracking=True,
        help="Method names separated by commas, e.g. action_confirm, button_validate. The run_action tool "
             "runs them.",
    )
    max_records = fields.Integer(string="Max Records at Once", default=50, tracking=True,
                                 help="0 = no limit.")
    user_ids = fields.Many2many(
        "res.users", "mcp_rule_user_rel", "rule_id", "user_id", string="Users",
        domain=[("share", "=", False)], help="Empty = all internal users.",
    )
    note = fields.Text(string="Note")

    # --- výpočty a kontroly --------------------------------------------------------------------

    @api.depends("privilege_id", "extra_model_ids", "excluded_model_ids")
    def _compute_model_ids(self):
        IrModel = self.env["ir.model"].sudo()
        for rule in self:
            models_ = IrModel.search([("model", "in", sorted(rule._get_model_names()))])
            rule.model_ids = models_
            rule.model_count = len(models_)

    @api.depends("perm_create", "perm_write", "perm_archive", "perm_unlink", "perm_note", "action_names",
                 "field_ids", "domain", "max_records", "model_count")
    @api.depends_context("lang")
    def _compute_summary(self):
        for rule in self:
            _ = self.env._
            operations = [_(label) for fname, label in OPERATION_FIELDS.items() if rule[fname]]
            if rule._get_action_names():
                operations.append(_("actions %s", ", ".join(rule._get_action_names())))
            parts = [
                ", ".join(operations) or _("nothing"),
                _("models: %s", rule.model_count),
                _("fields: listed only (%s)", len(rule.field_ids)) if rule.field_ids else _("fields: all unprotected"),
                _("records: matching the domain only") if (rule.domain or "").strip() else _("records: all"),
            ]
            if rule.max_records:
                parts.append(_("at most %s at once", rule.max_records))
            rule.summary = " · ".join(parts)

    @api.onchange("privilege_id")
    def _onchange_privilege_id(self):
        if self.privilege_id and not self.name:
            self.name = self.privilege_id.name

    @api.constrains("domain")
    def _check_domain(self):
        for rule in self:
            try:
                domain = rule._get_domain()
            except Exception as error:  # noqa: BLE001 – uživatel dostane srozumitelnou chybu
                raise ValidationError(self.env._("The domain of rule %(name)s is not valid: %(error)s",
                                                 name=rule.name, error=str(error))) from error
            if domain is not None and not isinstance(domain, (list, tuple)):
                raise ValidationError(self.env._("The domain of rule %s must be a list.", rule.name))

    # --- schvalování ---------------------------------------------------------------------------

    def _check_human_approval(self):
        """Schvalovat smí jen administrátor v Odoo, nikdy volání přes MCP (i když běží pod adminem)."""
        if self.env.context.get("mcp_request"):
            raise AccessError(self.env._("MCP rules cannot be approved or changed via MCP."))
        if not self.env.is_superuser() and not self.env.user.has_group("base.group_system"):
            raise AccessError(self.env._("Only an administrator (Settings) can approve MCP rules."))

    @api.model_create_multi
    def create(self, vals_list):
        if self.env.context.get("mcp_request"):
            # přes MCP vzniká jen návrh, i kdyby volající poslal něco jiného
            vals_list = [{**{k: v for k, v in vals.items() if k not in APPROVAL_FIELDS}, "state": "proposed"}
                         for vals in vals_list]
        return super().create(vals_list)

    def write(self, vals):
        if self.env.context.get("mcp_request"):
            raise AccessError(self.env._("MCP rules cannot be approved or changed via MCP."))
        if APPROVAL_FIELDS & set(vals) and not self.env.context.get("mcp_approval"):
            self._check_human_approval()
        return super().write(vals)

    def action_approve(self):
        self._check_human_approval()
        self.with_context(mcp_approval=True).write({
            "state": "approved", "approved_by_id": self.env.user.id, "approved_date": fields.Datetime.now(),
        })
        self.activity_ids.action_feedback(feedback=self.env._("Approved"))
        return True

    def action_reject(self):
        self._check_human_approval()
        self.with_context(mcp_approval=True).write({"state": "rejected", "approved_by_id": False, "approved_date": False})
        self.activity_ids.action_feedback(feedback=self.env._("Rejected"))
        return True

    def action_reset_to_proposed(self):
        self._check_human_approval()
        self.with_context(mcp_approval=True).write({"state": "proposed", "approved_by_id": False, "approved_date": False})
        return True

    @api.model
    def _create_proposal(self, user, values: dict, client_name: str, reason: str):
        """Návrh pravidla od AI: neplatí, dokud ho člověk neschválí. Uživateli přibude aktivita."""
        rule = self.sudo().with_context(mcp_request=True, mail_create_nosubscribe=True).create({
            **values,
            "proposed_by_id": user.id,
            "proposal_client": client_name,
            "proposal_reason": reason,
            "user_ids": [(6, 0, [user.id])],
        })
        rule = rule.with_context(mcp_request=False)
        activity_type = self.env.ref("mail.mail_activity_data_todo", raise_if_not_found=False)
        if activity_type:
            rule.sudo().with_context(mail_activity_quick_update=True).activity_schedule(
                activity_type_id=activity_type.id, user_id=user.id,
                summary=self.env._("Approve MCP rule: %s", rule.name),
                note=self.env._("Proposed by %(client)s: %(reason)s", client=client_name, reason=reason),
            )
        return rule

    # --- pro kontrolu přístupu -----------------------------------------------------------------

    @api.model
    def _privilege_model_names(self, privilege_id: int) -> set[str]:
        self.env.cr.execute(SQL(PRIVILEGE_MODELS_SQL, privilege_id))
        registry = self.env.registry
        return {name for (name,) in self.env.cr.fetchall()
                if name in registry and not registry[name]._transient and not registry[name]._abstract}

    def _get_model_names(self) -> set[str]:
        self.ensure_one()
        names = self._privilege_model_names(self.privilege_id.id) if self.privilege_id else set()
        names |= set(self.sudo().extra_model_ids.mapped("model"))
        names -= set(self.sudo().excluded_model_ids.mapped("model"))
        registry = self.env.registry
        return {name for name in names
                if name in registry and not registry[name]._transient and not registry[name]._abstract}

    def _get_field_names(self, model_name: str) -> frozenset[str] | None:
        """None = všechna pole; jinak vyjmenovaná pole pro tenhle model (může být prázdné)."""
        self.ensure_one()
        fields_ = self.sudo().field_ids
        if not fields_:
            return None
        return frozenset(fields_.filtered(lambda f: f.model == model_name).mapped("name"))

    def _get_domain(self):
        self.ensure_one()
        if not (self.domain or "").strip():
            return None
        return safe_eval(self.domain, {"user": self.env.user, "uid": self.env.uid, "time": safe_time})

    def _get_action_names(self) -> list[str]:
        self.ensure_one()
        return [name.strip() for name in (self.action_names or "").split(",") if name.strip()]
