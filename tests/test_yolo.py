# -*- coding: utf-8 -*-
import json

from odoo.exceptions import AccessError
from odoo.fields import Command
from odoo.tests import TransactionCase, tagged

from ..lib import oauth, policy, protocol, tools
from ..lib.policy import McpContext, PolicyError
from .test_policy import make_admin


@tagged("post_install", "-at_install")
class TestYolo(TransactionCase):
    """YOLO: všechna práva Odoo uživatele bez pravidel MCP; tajné údaje a nastavení MCP zůstávají mimo."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = make_admin(cls.env, "mcp_yolo")
        cls.user.mcp_yolo = True
        cls.partner = cls.env["res.partner"].create({"name": "Žluťoučký kůň s.r.o.", "is_company": True})

    def ctx(self, write=True, yolo=True):
        scopes = {oauth.SCOPE_READ, oauth.SCOPE_WRITE} if write else {oauth.SCOPE_READ}
        return McpContext(env=self.env(user=self.user.id), base_url="http://odoo.test", scopes=frozenset(scopes),
                          client_name="Test", yolo=yolo)

    def call(self, ctx, tool, /, **arguments):
        return tools.call_tool(ctx, tool, arguments)

    def test_off_by_default(self):
        self.assertFalse(make_admin(self.env, "mcp_plain").mcp_yolo)
        ctx = self.ctx(yolo=False)
        self.assertFalse(policy.model_allowed(ctx, "ir.module.module"))
        self.assertNotIn(self.env.ref("base.group_system").id, policy.effective_group_ids(ctx))

    def test_admin_rights_and_technical_models(self):
        ctx = self.ctx()
        self.assertIn(self.env.ref("base.group_system").id, policy.effective_group_ids(ctx))
        self.assertTrue(policy.groups_allowed(ctx, "base.group_system"))
        for model in ("ir.module.module", "ir.cron", "res.groups", "res.config.settings"):
            self.assertTrue(policy.model_allowed(ctx, model), model)
        self.assertTrue(policy.model_allowed(ctx, "res.company", "write"))
        self.assertTrue(policy.model_allowed(ctx, "res.users", "write"))
        result, status, message = self.call(ctx, "search_read", model="ir.module.module",
                                            domain=[["name", "=", "base"]], fields=["name", "state"])
        self.assertEqual(status, "ok", message)
        self.assertIn('"state":"installed"', result["content"][0]["text"])

    def test_writes_without_rules(self):
        ctx = self.ctx()
        names = {tool.name for tool in tools.list_tools(ctx)}
        self.assertTrue({"create_record", "update_record", "archive_record", "delete_record", "run_action"} <= names)
        result, status, message = self.call(ctx, "create_record", model="res.partner", values={"name": "Nový"})
        self.assertEqual(status, "ok", message)
        created = self.env["res.partner"].browse(json.loads(result["content"][0]["text"])["id"])
        self.assertEqual(created.name, "Nový")
        self.assertIn("Test, YOLO", created.message_ids[:1].body)
        _result, status, message = self.call(ctx, "update_record", model="res.company", ids=[self.env.company.id],
                                             values={"phone": "+420 111 222 333"})
        self.assertEqual(status, "ok", message)
        self.assertEqual(self.env.company.phone, "+420 111 222 333")
        _result, status, message = self.call(ctx, "run_action", model="res.partner", ids=[self.partner.id],
                                             method="address_get")
        self.assertEqual(status, "ok", message)
        self.assertEqual(tools.writable_operations(ctx, "res.partner"),
                         ["action", "archive", "create", "note", "unlink", "write"])

    def test_read_only_connection_stays_read_only(self):
        ctx = self.ctx(write=False)
        self.assertNotIn("create_record", {tool.name for tool in tools.list_tools(ctx)})
        with self.assertRaisesRegex(PolicyError, "read-only"):
            policy.check_write(ctx, "res.partner", "create", values={"name": "X"})
        _result, status, _message = self.call(ctx, "create_record", model="res.partner", values={"name": "X"})
        self.assertEqual(status, "denied")

    def test_secrets_and_mcp_settings_stay_out(self):
        ctx = self.ctx()
        self.assertFalse(policy.field_readable(ctx, "res.users", "password"))
        self.assertFalse(policy.field_readable(ctx, "ir.mail_server", "smtp_pass"))
        for model in ("mcp.rule", "mcp.oauth.grant", "res.users.apikeys", "ir.config_parameter"):
            self.assertFalse(policy.model_allowed(ctx, model), model)
        with self.assertRaisesRegex(PolicyError, "setting of the MCP server"):
            policy.check_write(ctx, "res.users", "write", records=self.user, values={"mcp_yolo": False})
        with self.assertRaisesRegex(PolicyError, "setting of the MCP server"):
            policy.check_write(ctx, "res.company", "write", records=self.env.company, values={"mcp_about": "x"})
        with self.assertRaisesRegex(PolicyError, "cannot be run via MCP"):
            policy.check_action(ctx, "res.partner", "sudo", self.partner)

    def test_hidden_fields_are_shown(self):
        self.env["ir.model.fields"]._get("res.partner", "comment").mcp_hidden = True
        self.assertFalse(policy.field_readable(self.ctx(yolo=False), "res.partner", "comment"))
        self.assertTrue(policy.field_readable(self.ctx(), "res.partner", "comment"))

    def test_whoami_and_instructions_say_so(self):
        ctx = self.ctx()
        result, status, message = self.call(ctx, "whoami")
        self.assertEqual(status, "ok", message)
        data = json.loads(result["content"][0]["text"])
        self.assertIs(data["yolo"], True)
        self.assertIn("YOLO mode", data["admin_rights"])
        self.assertIn("YOLO mode is on", protocol.instructions(ctx))
        self.assertNotIn("YOLO", protocol.instructions(self.ctx(yolo=False)))

    def test_only_administrators_switch_it(self):
        clerk = self.env["res.users"].create({
            "name": "Clerk", "login": "mcp_clerk", "group_ids": [Command.set([self.env.ref("base.group_user").id])],
        })
        with self.assertRaises(AccessError):
            clerk.with_user(clerk).write({"mcp_yolo": True})
