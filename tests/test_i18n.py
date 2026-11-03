# -*- coding: utf-8 -*-
from odoo.tests import TransactionCase, tagged

from ..lib import oauth, policy, protocol, tools
from ..lib.i18n import error_text
from ..lib.policy import McpContext, PolicyError
from .test_policy import make_admin


@tagged("post_install", "-at_install")
class TestTranslations(TransactionCase):
    """Texty pro AI i pro člověka v jazyce uživatele: angličtina je zdroj, čeština z i18n/cs.po."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["res.lang"]._activate_lang("cs_CZ")
        cls.user = make_admin(cls.env, "mcp_i18n")

    def ctx(self, lang, write=True):
        """Jako controller MCP: kontext s jazykem uživatele (context_get)."""
        scopes = {oauth.SCOPE_READ, oauth.SCOPE_WRITE} if write else {oauth.SCOPE_READ}
        env = self.env(user=self.user.id, context={**self.env.context, "lang": lang})
        return McpContext(env=env, base_url="http://odoo.test", scopes=frozenset(scopes), client_name="Test")

    def definitions(self, lang):
        ctx = self.ctx(lang)
        return {tool.name: tools.tool_definition(ctx, tool) for tool in tools.list_tools(ctx)}

    def test_tool_definitions(self):
        english, czech = self.definitions("en_US"), self.definitions("cs_CZ")
        self.assertEqual(english["search_read"]["title"], "Search records")
        self.assertEqual(czech["search_read"]["title"], "Hledat záznamy")
        self.assertEqual(czech["search_read"]["annotations"]["title"], "Hledat záznamy")
        self.assertIn("Technický název modelu", czech["search_read"]["inputSchema"]["properties"]["model"]["description"])
        self.assertIn("Technical model name", english["search_read"]["inputSchema"]["properties"]["model"]["description"])
        self.assertTrue(czech["whoami"]["description"].startswith("Odoo "), "název systému zůstává před popisem")

    def test_errors(self):
        arguments = {"model": "res.partner", "ids": [999999999]}
        _result, status, message = tools.call_tool(self.ctx("cs_CZ"), "read_records", arguments)
        self.assertEqual(status, "denied")
        self.assertEqual(message, "Záznamy 999999999 modelu res.partner neexistují.")
        _result, _status, message = tools.call_tool(self.ctx("en_US"), "read_records", arguments)
        self.assertEqual(message, "Records 999999999 of model res.partner do not exist.")

    def test_nested_texts(self):
        """Hláška složená z víc textů a s přeloženým parametrem (druh operace)."""
        ctx = self.ctx("cs_CZ")
        with self.assertRaises(PolicyError) as caught:
            policy.check_write(ctx, "res.partner", "unlink", records=self.env["res.partner"])
        czech = error_text(ctx.env, caught.exception)
        self.assertIn("Pravidla MCP nepovolují mazání u modelu res.partner.", czech)
        self.assertIn("Navrhni pravidlo nástrojem propose_rule", czech)
        self.assertIn("MCP rules do not allow deleting on model res.partner.", str(caught.exception),
                      "str() výjimky je anglicky (logy)")

    def test_instructions_and_summary(self):
        self.assertIn("## Jak pracovat s tímhle serverem", protocol.instructions(self.ctx("cs_CZ")))
        self.assertIn("## How to work with this server", protocol.instructions(self.ctx("en_US")))
        rule = self.env["mcp.rule"].create({"name": "Kontakty", "perm_create": True, "extra_model_ids": [
            (6, 0, [self.env["ir.model"]._get("res.partner").id])]})
        self.assertTrue(rule.with_context(lang="cs_CZ").summary.startswith("zakládat · modelů: 1"))
        self.assertTrue(rule.with_context(lang="en_US").summary.startswith("create · models: 1"))

    def test_tool_records_follow_language(self):
        record = self.env["mcp.tool"].search([("name", "=", "draft_reply")])
        self.assertEqual(record.with_context(lang="cs_CZ").title, "Připravit odpověď")
        self.assertEqual(record.with_context(lang="en_US").title, "Draft reply")

    def test_oauth_errors_stay_english_for_clients(self):
        error = oauth.OAuthError("invalid_grant", oauth._lt("The client metadata document is not valid JSON."))
        self.assertEqual(error.as_dict()["error_description"], "The client metadata document is not valid JSON.")
        self.assertEqual(error.description_for(self.env(context={"lang": "cs_CZ"})), "Popis klienta není platný JSON.")
