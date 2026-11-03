# -*- coding: utf-8 -*-
import json
from unittest.mock import patch

from odoo.exceptions import AccessError
from odoo.fields import Command
from odoo.tests import TransactionCase, tagged

from ..lib import oauth, policy, protocol, tools
from ..lib.policy import McpContext, PolicyError


def make_admin(env, login="mcp_admin"):
    """Administrátor: Nastavení, Přístupová práva a zakládání kontaktů."""
    return env["res.users"].create({
        "name": "MCP Admin",
        "login": login,
        "password": "mcp-test-password-123",
        "group_ids": [Command.set([
            env.ref("base.group_user").id,
            env.ref("base.group_partner_manager").id,
            env.ref("base.group_system").id,
        ])],
    })


def make_ctx(env, user, write=True):
    scopes = {oauth.SCOPE_READ, oauth.SCOPE_WRITE} if write else {oauth.SCOPE_READ}
    return McpContext(env=env(user=user.id), base_url="http://odoo.test", scopes=frozenset(scopes),
                      client_name="Test")


@tagged("post_install", "-at_install")
class TestPolicy(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = make_admin(cls.env)
        cls.partner = cls.env["res.partner"].create({"name": "Žluťoučký kůň s.r.o.", "is_company": True})
        cls.person = cls.env["res.partner"].create({"name": "Jan Novák", "parent_id": cls.partner.id})

    def ctx(self, write=True):
        return make_ctx(self.env, self.user, write)

    def call(self, ctx, tool, /, **arguments):
        result, status, message = tools.call_tool(ctx, tool, arguments)
        return result, status, message

    def make_rule(self, **values):
        return self.env["mcp.rule"].create({
            "name": "Kontakty",
            "extra_model_ids": [Command.set([self.env["ir.model"]._get("res.partner").id])],
            **values,
        })

    # --- čtení ---------------------------------------------------------------------------------

    def test_admin_models_hidden(self):
        ctx = self.ctx()
        self.assertTrue(policy.model_allowed(ctx, "res.partner"))
        for model in ("ir.config_parameter", "res.users.apikeys", "ir.cron", "res.groups", "mcp.rule", "mail.message"):
            self.assertFalse(policy.model_allowed(ctx, model), model)
        self.assertNotIn("ir.config_parameter", policy.readable_models(ctx))
        self.assertTrue(policy.model_allowed(ctx, "res.users", "read"))
        self.assertFalse(policy.model_allowed(ctx, "res.users", "write"),
                         "úprava uživatelů je administrátorské právo, přes MCP neplatí")

    def test_admin_groups_removed(self):
        ctx = self.ctx()
        groups = policy.effective_group_ids(ctx)
        self.assertNotIn(self.env.ref("base.group_system").id, groups)
        self.assertNotIn(self.env.ref("base.group_erp_manager").id, groups)
        self.assertIn(self.env.ref("base.group_partner_manager").id, groups)
        self.assertFalse(policy.groups_allowed(ctx, "base.group_system"))
        self.assertTrue(policy.groups_allowed(ctx, "base.group_user,base.group_portal"))
        self.assertFalse(policy.groups_allowed(ctx, "!base.group_user"))

    def test_sensitive_and_hidden_fields(self):
        ctx = self.ctx()
        self.assertFalse(policy.field_readable(ctx, "res.users", "password"))
        self.assertTrue(policy.field_readable(ctx, "res.partner", "email"))
        self.env["ir.model.fields"]._get("res.partner", "comment").mcp_hidden = True
        ctx = self.ctx()
        self.assertFalse(policy.field_readable(ctx, "res.partner", "comment"))
        with self.assertRaises(PolicyError):
            policy.check_domain(ctx, "res.partner", [["comment", "ilike", "tajné"]])
        with self.assertRaises(PolicyError):
            policy.check_order(ctx, "res.partner", "comment desc")
        with self.assertRaises(PolicyError):
            policy.check_domain(ctx, "res.partner", [["user_ids.password", "=", "x"]])
        policy.check_domain(ctx, "res.partner", ["|", ["name", "ilike", "kůň"], ["parent_id.name", "=", "x"]])
        _result, status, message = self.call(ctx, "search_read", model="res.partner", fields=["comment"])
        self.assertEqual(status, "denied")
        self.assertIn("exist but cannot be read", message)

    def test_unknown_field_is_error_with_suggestions(self):
        """Neexistující pole (překlep, název ze starší verze Odoo) je chyba s podobnými názvy, ne odmítnutí."""
        ctx = self.ctx(write=False)
        _result, status, message = self.call(ctx, "search_read", model="res.partner",
                                             fields=["name", "partner_country_id"])
        self.assertEqual(status, "error")
        self.assertIn("Field partner_country_id does not exist on model res.partner.", message)
        self.assertIn("Similar fields: country_id (Country)", message)
        self.assertNotIn("hidden", message)
        _result, status, message = self.call(ctx, "count_records", model="res.partner",
                                             domain=[["parent_id.e_mail", "=", "x"]])
        self.assertEqual(status, "error")
        self.assertIn("Field e_mail does not exist on model res.partner. Similar fields: email (Email)", message)
        _result, status, message = self.call(ctx, "search_read", model="res.partner", fields=["xyz"], order="xyz")
        self.assertEqual(message, "Field xyz does not exist on model res.partner. "
                                  "describe_model lists all available fields.")
        self.env["ir.model.fields"]._get("res.partner", "comment").mcp_hidden = True
        self.assertNotIn("comment", policy.similar_fields(self.ctx(), "res.partner", "coment"),
                         "skryté pole se nenabízí")

    def test_search_read_tool(self):
        result, status, _message = self.call(self.ctx(write=False), "search_read", model="res.partner",
                                             domain=[["id", "=", self.partner.id]], fields=["name", "is_company"])
        self.assertEqual(status, "ok")
        self.assertIn("Žluťoučký kůň s.r.o.", result["content"][0]["text"])
        result, status, message = self.call(self.ctx(), "search_read", model="ir.config_parameter")
        self.assertEqual(status, "denied")
        self.assertTrue(result["isError"])

    def extra_tools(self, extra):
        """Nástroje z jiného addonu: jako by addon zdědil mcp.tool a přepsal _mcp_extra_tools."""
        return patch.object(type(self.env["mcp.tool"]), "_mcp_extra_tools", lambda model: list(extra))

    def test_read_tools_never_write(self):
        """Nástroj pro čtení běží v savepointu, který se vždy vrátí zpět."""
        tool = tools.Tool("broken_reader", "x", "x", tools.schema({}),
                          lambda c, a: self.partner.write({"name": "Změněno"}) or {}, tools.READ_ANNOTATIONS)
        with self.extra_tools([tool]):
            _result, status, message = self.call(self.ctx(), "broken_reader")
        self.assertEqual(status, "ok", message)
        self.partner.invalidate_recordset()
        self.assertEqual(self.partner.name, "Žluťoučký kůň s.r.o.")

    def test_extra_tools_from_other_addons(self):
        def echo(ctx, args):
            return {"echo": args.get("text"), "user": ctx.env.user.login}

        extra = [
            tools.Tool("demo_echo", "Ozvěna", "Vrátí text.", tools.schema({"text": {"type": "string"}}), echo,
                       tools.READ_ANNOTATIONS, instructions="Ozvěnu používej jen na zkoušku spojení."),
            tools.Tool("demo_admin", "Jen správci", "x", tools.schema({}), echo, tools.READ_ANNOTATIONS,
                       kind="admin", default_groups=("base.group_system",)),
            tools.Tool("demo_write", "Zápis", "x", tools.schema({}), echo,
                       {"readOnlyHint": False}, readonly=False, operation="write"),
            tools.Tool("whoami", "Kolize s vestavěným", "x", tools.schema({}), echo, tools.READ_ANNOTATIONS),
            tools.Tool("Špatný název", "x", "x", tools.schema({}), echo, tools.READ_ANNOTATIONS),
            "není nástroj",
        ]
        with self.extra_tools(extra), self.assertLogs("odoo.addons.mcp_oauth_server.lib.tools", "ERROR") as logs:
            ctx = self.ctx()
            names = [tool.name for tool in tools.list_tools(ctx)]
            self.assertIn("demo_echo", names)
            self.assertNotIn("demo_write", names, "zápis z jiného addonu taky řídí pravidla")
            self.assertEqual(names.count("whoami"), 1, "vestavěný nástroj nejde přepsat")
            result, status, message = self.call(ctx, "demo_echo", text="ahoj")
            self.assertEqual(status, "ok", message)
            self.assertEqual(json.loads(result["content"][0]["text"]), {"echo": "ahoj", "user": "mcp_admin"})
            self.assertIn("Ozvěnu používej jen na zkoušku spojení.", protocol.instructions(ctx))

            self.env["mcp.tool"].init()
            echo_record = self.env["mcp.tool"].search([("name", "=", "demo_echo")])
            self.assertEqual(echo_record.module, "mcp_oauth_server")
            self.assertTrue(echo_record.available)
            admin_record = self.env["mcp.tool"].search([("name", "=", "demo_admin")])
            self.assertEqual(admin_record.kind, "admin")
            self.assertEqual(admin_record.group_ids, self.env.ref("base.group_system"))
            echo_record.enabled = False
            self.assertNotIn("demo_echo", [tool.name for tool in tools.list_tools(self.ctx())])
        self.assertEqual(len(logs.output), 3, "kolize, špatný název a cizí objekt se jen zapíšou do logu")
        echo_record.invalidate_recordset(["available"])
        self.assertFalse(echo_record.available, "po odinstalaci addonu záznam zůstane, AI nástroj nevidí")

    # --- zápis ---------------------------------------------------------------------------------

    def test_write_needs_scope_and_rule(self):
        with self.assertRaisesRegex(PolicyError, "read-only"):
            policy.check_write(self.ctx(write=False), "res.partner", "write", records=self.partner, values={"name": "X"})
        with self.assertRaisesRegex(PolicyError, "MCP rules do not allow"):
            policy.check_write(self.ctx(), "res.partner", "write", records=self.partner, values={"name": "X"})
        names = {t.name for t in tools.list_tools(self.ctx())}
        self.assertNotIn("create_record", names)
        self.make_rule(perm_write=True)
        names = {t.name for t in tools.list_tools(self.ctx())}
        self.assertIn("update_record", names)
        self.assertNotIn("create_record", names)
        self.assertNotIn("update_record", {t.name for t in tools.list_tools(self.ctx(write=False))})

    def test_rule_fields_and_preview(self):
        self.make_rule(perm_create=True, perm_write=True, field_ids=[Command.set([
            self.env["ir.model.fields"]._get("res.partner", name).id for name in ("name", "email", "child_ids")
        ])])
        ctx = self.ctx()
        result, status, message = self.call(ctx, "create_record", model="res.partner",
                                            values={"name": "Nový dodavatel", "email": "info@dodavatel.test"})
        self.assertEqual(status, "ok", message)
        self.assertTrue(self.env["res.partner"].search_count([("name", "=", "Nový dodavatel")]))
        _result, status, message = self.call(ctx, "create_record", model="res.partner",
                                             values={"name": "Nový dodavatel", "comment": "x"})
        self.assertEqual(status, "denied")
        self.assertIn("comment", message)
        # vnořené řádky musí projít stejnými pravidly
        _result, status, message = self.call(ctx, "update_record", model="res.partner", ids=[self.partner.id],
                                             values={"child_ids": [[0, 0, {"name": "Nový", "comment": "x"}]]})
        self.assertEqual(status, "denied", message)
        # neexistující pole je chyba i u zápisu, i ve vnořených řádcích
        _result, status, message = self.call(ctx, "update_record", model="res.partner", ids=[self.partner.id],
                                             values={"e_mail": "x@dodavatel.test"})
        self.assertEqual(status, "error", message)
        self.assertIn("email (Email)", message)
        _result, status, message = self.call(ctx, "update_record", model="res.partner", ids=[self.partner.id],
                                             values={"child_ids": [[0, 0, {"name": "Nový", "e_mail": "x"}]]})
        self.assertEqual(status, "error", message)
        # náhled nic neuloží
        result, status, message = self.call(ctx, "create_record", model="res.partner",
                                            values={"name": "Jen náhled"}, preview=True)
        self.assertEqual(status, "ok", message)
        self.assertFalse(self.env["res.partner"].search_count([("name", "=", "Jen náhled")]))

    def test_rule_domain_users_and_limits(self):
        rule = self.make_rule(perm_write=True, domain="[('name', 'ilike', 'Žluťoučký')]", max_records=1)
        ctx = self.ctx()
        policy.check_write(ctx, "res.partner", "write", records=self.partner, values={"name": "Firma"})
        with self.assertRaisesRegex(PolicyError, "do not match"):
            policy.check_write(ctx, "res.partner", "write", records=self.person, values={"name": "X"})
        with self.assertRaisesRegex(PolicyError, "at most 1"):
            policy.check_write(ctx, "res.partner", "write", records=self.partner | self.person, values={"name": "X"})
        other = make_admin(self.env, "mcp_other")
        rule.user_ids = other
        with self.assertRaisesRegex(PolicyError, "MCP rules do not allow"):
            policy.check_write(self.ctx(), "res.partner", "write", records=self.partner, values={"name": "Firma"})

    def test_unlink_and_actions_need_explicit_rule(self):
        self.make_rule(perm_write=True, action_names="action_archive, toggle_active")
        ctx = self.ctx()
        with self.assertRaisesRegex(PolicyError, "MCP rules do not allow"):
            policy.check_write(ctx, "res.partner", "unlink", records=self.person)
        with self.assertRaisesRegex(PolicyError, "cannot be run via MCP"):
            policy.check_action(ctx, "res.partner", "toggle_active", self.person)
        with self.assertRaisesRegex(PolicyError, "cannot be run via MCP"):
            policy.check_action(ctx, "res.partner", "_compute_display_name", self.person)

    # --- návrhy pravidel od AI ----------------------------------------------------------------

    def test_proposal_needs_human_approval(self):
        ctx = self.ctx(write=False)  # navrhnout jde i ze spojení jen pro čtení
        result, status, message = self.call(ctx, "propose_rule", name="Kontakty: úpravy", reason="Oprava e-mailů",
                                            models=["res.partner"], operations=["write"],
                                            fields={"res.partner": ["email"]})
        self.assertEqual(status, "ok", message)
        rule = self.env["mcp.rule"].search([("name", "=", "Kontakty: úpravy")])
        self.assertEqual(rule.state, "proposed")
        self.assertEqual(rule.proposed_by_id, self.user)
        self.assertEqual(rule.user_ids, self.user, "návrh platí jen pro toho, kdo ho přes AI navrhl")
        self.assertEqual(rule.field_ids.mapped("name"), ["email"])
        self.assertTrue(rule.activity_ids, "uživatel má úkol návrh schválit")
        with self.assertRaisesRegex(PolicyError, "propose_rule"):
            policy.check_write(self.ctx(), "res.partner", "write", records=self.partner, values={"email": "a@b.cz"})
        rule.action_approve()
        self.assertEqual(rule.state, "approved")
        self.assertFalse(rule.activity_ids)
        policy.check_write(self.ctx(), "res.partner", "write", records=self.partner, values={"email": "a@b.cz"})
        with self.assertRaisesRegex(PolicyError, "does not allow field name"):
            policy.check_write(self.ctx(), "res.partner", "write", records=self.partner, values={"name": "X"})

    def test_proposal_cannot_be_approved_through_mcp(self):
        Rule = self.env["mcp.rule"].with_context(mcp_request=True)
        rule = Rule.create({"name": "Podvržené", "state": "approved", "perm_write": True,
                            "approved_by_id": self.user.id})
        self.assertEqual(rule.state, "proposed", "přes MCP vzniká vždy jen návrh")
        self.assertFalse(rule.approved_by_id)
        with self.assertRaises(AccessError):
            rule.action_approve()
        with self.assertRaises(AccessError):
            rule.write({"state": "approved"})
        with self.assertRaises(AccessError):
            rule.write({"perm_unlink": True})
        with self.assertRaises(AccessError, msg="schvaluje jen správce"):
            rule.with_context(mcp_request=False).with_user(self.env.ref("base.public_user")).action_approve()

    def test_proposal_validation(self):
        self.env["ir.model.fields"]._get("res.partner", "comment").mcp_hidden = True
        ctx = self.ctx()
        _result, status, message = self.call(ctx, "propose_rule", name="X", reason="test", models=["res.partner"],
                                             operations=["write"], fields={"res.partner": ["password"]})
        self.assertEqual(status, "error", "res.partner pole password nemá")
        self.assertIn("does not exist", message)
        for arguments, expected in (
            ({"models": ["ir.config_parameter"], "operations": ["write"]}, "is not available via MCP"),
            ({"app": "Neexistující aplikace", "operations": ["write"]}, "Available apps"),
            ({"models": ["res.partner"], "operations": ["fly"]}, "operations"),
            ({"models": ["res.partner"], "operations": []}, "has to allow something"),
            ({"models": ["res.partner"], "operations": ["write"], "fields": {"res.users": ["name"]}}, "does not cover"),
            ({"models": ["res.partner"], "operations": ["write"], "fields": {"res.partner": ["comment"]}}, "hidden"),
            ({"models": ["res.partner"], "actions": ["unlink"]}, "actions"),
            ({"models": ["res.partner"], "operations": ["write"], "domain": "name = x"}, "domain"),
        ):
            _result, status, message = self.call(ctx, "propose_rule", name="X", reason="test", **arguments)
            self.assertEqual(status, "denied", arguments)
            self.assertIn(expected, message, arguments)
        self.assertFalse(self.env["mcp.rule"].search_count([("name", "=", "X")]))

    # --- pokyny pro AI a nastavení nástrojů --------------------------------------------------

    def test_company_instructions_come_first(self):
        self.user.company_id.write({
            "mcp_system_name": "Odoo Žluťoučký kůň",
            "mcp_about": "Velkoobchod s ovocem a zeleninou.",
            "mcp_instructions": "- Ceny uváděj vždy s DPH.",
        })
        ctx = self.ctx()
        text = protocol.instructions(ctx)
        self.assertTrue(text.startswith("# Odoo Žluťoučký kůň"))
        self.assertLess(text.index("Ceny uváděj vždy s DPH"), text.index("How to work with this server"))
        self.assertEqual(protocol.initialize(ctx, {}, "1")["serverInfo"]["title"], "Odoo Žluťoučký kůň")
        result, status, _message = self.call(ctx, "whoami")
        data = json.loads(result["content"][0]["text"])
        self.assertEqual(data["system"]["rules_for_ai"], "- Ceny uváděj vždy s DPH.")
        self.assertNotIn("setup_needed", data["system"], "popis firmy je vyplněný, AI se nemá ptát")
        whoami = tools.tool_definition(ctx, tools.tools_by_name(ctx)["whoami"])
        self.assertTrue(whoami["description"].startswith("Odoo Žluťoučký kůň:"))

    def test_whoami_asks_for_company_description(self):
        """Bez popisu firmy AI dostane pokyn zeptat se uživatele a navrhnout text do Pokynů pro AI."""
        self.user.company_id.write({"mcp_about": False, "mcp_instructions": False})
        result, _status, _message = self.call(self.ctx(), "whoami")
        hint = json.loads(result["content"][0]["text"])["system"]["setup_needed"]
        self.assertIn("ask the user once what the company does", hint)
        self.assertIn("http://odoo.test/odoo/mcp-ai-instructions", hint)
        self.assertNotIn("Only an administrator", hint, "správce si text uloží sám")
        employee = self.env["res.users"].create({
            "name": "Zaměstnanec", "login": "mcp_zamestnanec_firma", "password": "mcp-test-password-123",
            "group_ids": [Command.set([self.env.ref("base.group_user").id])],
        })
        result, _status, _message = self.call(make_ctx(self.env, employee), "whoami")
        self.assertIn("Only an administrator", json.loads(result["content"][0]["text"])["system"]["setup_needed"])

    def test_disabled_and_restricted_tools(self):
        Tool = self.env["mcp.tool"]
        self.assertTrue(Tool.search([("name", "=", "search_read")]), "nástroje se založí při instalaci")
        Tool.search([("name", "=", "search_read")]).enabled = False
        other = make_admin(self.env, "mcp_jiny")
        Tool.search([("name", "=", "count_records")]).user_ids = other
        Tool.search([("name", "=", "name_search")]).group_ids = self.env.ref("base.group_partner_manager")
        ctx = self.ctx()
        names = {t.name for t in tools.list_tools(ctx)}
        self.assertNotIn("search_read", names)
        self.assertNotIn("count_records", names)
        self.assertIn("name_search", names)
        _result, status, message = self.call(ctx, "search_read", model="res.partner")
        self.assertEqual(status, "denied")
        self.assertIn("disabled", message)
        self.assertIn("count_records", {t.name for t in tools.list_tools(make_ctx(self.env, other))})

    def test_propose_rule_only_for_admins_by_default(self):
        employee = self.env["res.users"].create({
            "name": "Zaměstnanec", "login": "mcp_zamestnanec", "password": "mcp-test-password-123",
            "group_ids": [Command.set([self.env.ref("base.group_user").id,
                                       self.env.ref("base.group_partner_manager").id])],
        })
        ctx = make_ctx(self.env, employee)
        self.assertNotIn("propose_rule", {t.name for t in tools.list_tools(ctx)})
        self.assertIn("propose_rule", {t.name for t in tools.list_tools(self.ctx())})
        with self.assertRaisesRegex(PolicyError, "Odoo administrator"):
            policy.check_write(ctx, "res.partner", "write", records=self.partner, values={"name": "X"})
        self.assertNotIn("propose_rule", protocol.instructions(ctx))

    def test_privilege_maps_models(self):
        privilege = self.env.ref("base.group_partner_manager").privilege_id
        self.assertTrue(privilege, "skupina Kontakty má mít řádek Přístupová práva")
        rule = self.env["mcp.rule"].create({"name": "Kontakty", "privilege_id": privilege.id, "perm_write": True})
        self.assertIn("res.partner", rule._get_model_names())
        self.assertNotIn("res.users", rule._get_model_names())
