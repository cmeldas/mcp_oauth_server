# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import fields
from odoo.tests import TransactionCase, tagged
from odoo.tools import SQL

from ..lib import tools
from .test_policy import make_admin, make_ctx


@tagged("post_install", "-at_install")
class TestDraftReply(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = make_admin(cls.env)
        cls.customer = cls.env["res.partner"].create({"name": "Zákazník", "email": "zakaznik@example.com"})

    def draft(self, write=False, **arguments):
        ctx = make_ctx(self.env, self.user, write=write)
        result, status, message = tools.call_tool(ctx, "draft_reply", {"model": "res.partner", "id": self.customer.id,
                                                                       **arguments})
        self.assertEqual(status, "ok", message)
        return self.env["mail.scheduled.message"].search([("model", "=", "res.partner"),
                                                          ("res_id", "=", self.customer.id), ("mcp_draft", "=", True)])

    def test_draft_is_prepared_not_sent(self):
        messages_before = len(self.customer.message_ids)
        draft = self.draft(body="Dobrý den,\nposílám řešení.\n\nS pozdravem\nJan")
        self.assertEqual(len(draft), 1, "návrh jde i ze spojení jen pro čtení")
        self.assertEqual(draft.author_id, self.user.partner_id)
        self.assertEqual(draft.create_uid, self.user, "autorem je uživatel, takže smí návrh odeslat")
        self.assertEqual(str(draft.body), "<p>Dobrý den,<br>posílám řešení.</p><p>S pozdravem<br>Jan</p>")
        self.assertIn(self.customer, draft.partner_ids, "příjemce jako u běžné odpovědi")
        self.assertTrue(draft.mcp_activity_id, "uživatel má aktivitu ke kontrole")
        self.assertEqual(len(self.customer.message_ids), messages_before, "nic se neodeslalo")

    def test_html_is_sanitized_and_draft_replaced(self):
        first = self.draft(body="První verze")
        activity = first.mcp_activity_id
        draft = self.draft(body='<p onclick="x()">Druhá <b>verze</b></p><script>alert(1)</script>')
        self.assertFalse(first.exists(), "starší návrh od AI na stejném záznamu se nahradí")
        self.assertFalse(activity.exists())
        self.assertIn("<b>verze</b>", str(draft.body))
        self.assertNotIn("script", str(draft.body))
        self.assertNotIn("onclick", str(draft.body))

    def test_cron_never_sends_draft(self):
        draft = self.draft(body="Návrh")
        normal = self.env["mail.scheduled.message"].with_user(self.user).create({
            "model": "res.partner", "res_id": self.customer.id, "body": "Naplánováno ručně",
            "author_id": self.user.partner_id.id, "scheduled_date": fields.Datetime.now() + timedelta(days=1),
        })
        past = fields.Datetime.now() - timedelta(days=1)
        self.env.cr.execute(SQL("UPDATE mail_scheduled_message SET scheduled_date = %s WHERE id IN %s",
                                past, (draft.id, normal.id)))
        self.env["mail.scheduled.message"].invalidate_model()
        self.env["mail.scheduled.message"]._post_messages_cron()
        self.assertTrue(draft.exists(), "návrh od AI cron neodešle")
        self.assertFalse(normal.exists(), "běžná naplánovaná zpráva se odeslala")

    def test_send_now_and_cancel(self):
        draft = self.draft(body="Odesílám")
        activity = draft.mcp_activity_id
        draft.with_user(self.user).post_message()
        self.assertFalse(draft.exists())
        self.assertFalse(activity.exists(), "po odeslání se aktivita uzavře")
        message = self.customer.message_ids[0]
        self.assertIn("Odesílám", message.body)
        self.assertEqual(message.message_type, "comment", "odejde jako běžná zpráva, ne systémové oznámení")
        self.assertEqual(message.author_id, self.user.partner_id)
        self.assertIn(self.customer, message.partner_ids)
        cancelled = self.draft(body="Zrušit")
        activity = cancelled.mcp_activity_id
        cancelled.with_user(self.user).unlink()
        self.assertFalse(activity.exists(), "po zrušení se aktivita smaže")

    def test_tool_can_be_disabled(self):
        self.env["mcp.tool"].search([("name", "=", "draft_reply")]).enabled = False
        ctx = make_ctx(self.env, self.user)
        _result, status, message = tools.call_tool(ctx, "draft_reply", {"model": "res.partner", "id": self.customer.id,
                                                                        "body": "x"})
        self.assertEqual(status, "denied")
        self.assertIn("disabled", message)
