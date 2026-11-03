# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.fields import Domain


class MailScheduledMessage(models.Model):
    """Návrh odpovědi od AI = naplánovaná zpráva, která se nikdy neodešle sama.

    V chatteru záznamu ji uživatel uvidí s tlačítky Odeslat hned, Upravit a Zrušit (standard Odoo).
    """
    _inherit = "mail.scheduled.message"

    mcp_draft = fields.Boolean(
        string="AI Draft", readonly=True,
        help="Prepared by an AI client via MCP. It is never sent automatically, only with the Send Now button.",
    )
    mcp_client = fields.Char(string="Prepared by Client", readonly=True)
    mcp_activity_id = fields.Many2one("mail.activity", string="Review Activity", ondelete="set null",
                                      readonly=True)

    @api.model
    def _post_messages_cron(self, limit=50):
        # cron hledá zprávy, kterým nastal čas; návrhy od AI z hledání vyřadit
        return super(MailScheduledMessage, self.with_context(mcp_skip_drafts=True))._post_messages_cron(limit=limit)

    @api.model
    def _search(self, domain, *args, **kwargs):
        if self.env.context.get("mcp_skip_drafts"):
            domain = Domain(domain) & Domain("mcp_draft", "=", False)
        return super()._search(domain, *args, **kwargs)

    def unlink(self):
        # odesláno i zrušeno: aktivita „zkontrolovat návrh“ už není potřeba
        activities = self.sudo().mcp_activity_id
        result = super().unlink()
        activities.exists().unlink()
        return result

    def _store_scheduled_message_fields(self, res):
        super()._store_scheduled_message_fields(res)
        res.extend(["mcp_draft"])
