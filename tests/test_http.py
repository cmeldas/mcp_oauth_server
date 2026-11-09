# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import re
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from odoo import fields
from odoo.fields import Command
from odoo.tests import HttpCase, tagged

from ..lib import oauth
from .test_policy import make_admin

PASSWORD = "mcp-test-password-123"
REDIRECT = "http://127.0.0.1:9/callback"
VERIFIER = "v" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


@tagged("post_install", "-at_install")
class TestMcpHttp(HttpCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = make_admin(cls.env)
        cls.partner = cls.env["res.partner"].create({"name": "Žluťoučký kůň Test", "is_company": True})

    # --- pomocné -------------------------------------------------------------------------------

    def mcp(self, token, method, params=None, message_id=1):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if message_id is not None:
            body["id"] = message_id
        return self.url_open("/api/mcp", data=json.dumps(body), headers=headers)

    def call_tool(self, token, tool, /, **arguments):
        response = self.mcp(token, "tools/call", {"name": tool, "arguments": arguments})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["result"]

    def register(self, redirect_uris=(REDIRECT,), method="none"):
        return self.url_open("/api/mcp/oauth/register", data=json.dumps({
            "client_name": "Test klient", "redirect_uris": list(redirect_uris),
            "token_endpoint_auth_method": method,
        }), headers={"Content-Type": "application/json"})

    def authorize(self, client_id, allow_write=False, scope="odoo.read odoo.write offline_access"):
        self.authenticate(self.user.login, PASSWORD)
        query = {
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "scope": scope,
            "state": "stav-123", "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "resource": f"{self.base_url()}/api/mcp",
        }
        page = self.url_open("/api/mcp/oauth/authorize?" + urlencode(query))
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("Allow", page.text)
        csrf = re.search(r'name="csrf_token"[^>]*?value="([^"]+)"', page.text).group(1)
        data = {**query, "csrf_token": csrf, "decision": "allow"}
        if allow_write:
            data["allow_write"] = "1"
        response = self.url_open("/api/mcp/oauth/authorize/decision", data=data, allow_redirects=False)
        self.assertEqual(response.status_code, 303, response.text)
        location = response.headers["Location"]
        self.assertTrue(location.startswith(REDIRECT))
        params = parse_qs(urlsplit(location).query)
        self.assertEqual(params["state"], ["stav-123"])
        self.assertEqual(params["iss"], [self.base_url()])
        return params["code"][0]

    def exchange(self, client_id, code, verifier=VERIFIER):
        return self.url_open("/api/mcp/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
            "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": f"{self.base_url()}/api/mcp",
        })

    def connect(self, allow_write=False):
        client_id = self.register().json()["client_id"]
        response = self.exchange(client_id, self.authorize(client_id, allow_write))
        self.assertEqual(response.status_code, 200, response.text)
        return client_id, response.json()

    # --- metadata a přihlášení -----------------------------------------------------------------

    def test_metadata(self):
        resource = self.url_open("/.well-known/oauth-protected-resource/api/mcp").json()
        self.assertEqual(resource["resource"], f"{self.base_url()}/api/mcp")
        self.assertEqual(resource["authorization_servers"], [self.base_url()])
        server = self.url_open("/.well-known/oauth-authorization-server").json()
        self.assertEqual(server["issuer"], self.base_url())
        self.assertEqual(server["code_challenge_methods_supported"], ["S256"])
        self.assertIn("none", server["token_endpoint_auth_methods_supported"])
        self.assertTrue(server["client_id_metadata_document_supported"])
        self.assertTrue(server["authorization_response_iss_parameter_supported"])
        self.assertIn("registration_endpoint", server)

    def test_unauthorized(self):
        response = self.mcp(None, "initialize")
        self.assertEqual(response.status_code, 401)
        challenge = response.headers["WWW-Authenticate"]
        self.assertIn('resource_metadata="', challenge)
        self.assertIn("/.well-known/oauth-protected-resource/api/mcp", challenge)
        response = self.mcp("mcpa_neplatny", "initialize")
        self.assertEqual(response.status_code, 401)
        self.assertIn('error="invalid_token"', response.headers["WWW-Authenticate"])
        self.assertEqual(self.url_open("/api/mcp").status_code, 405)

    def test_registration_rejects_foreign_redirect(self):
        response = self.register(["https://evil.example/callback"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_redirect_uri")
        response = self.register(["https://claude.ai/api/mcp/auth_callback"])
        self.assertEqual(response.status_code, 201)

    def test_full_flow_read_only(self):
        _client_id, tokens = self.connect()
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertNotIn("odoo.write", tokens["scope"].split(), "zápis je bez zaškrtnutí vypnutý")
        access = tokens["access_token"]
        init = self.mcp(access, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                               "clientInfo": {"name": "test", "version": "1"}})
        self.assertEqual(init.status_code, 200, init.text)
        self.assertEqual(init.json()["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(self.mcp(access, "notifications/initialized", message_id=None).status_code, 202)
        names = {t["name"] for t in self.mcp(access, "tools/list").json()["result"]["tools"]}
        self.assertIn("search_read", names)
        self.assertNotIn("create_record", names)
        result = self.call_tool(access, "search_read", model="res.partner", domain=[["id", "=", self.partner.id]])
        self.assertFalse(result.get("isError"), result)
        self.assertIn("Žluťoučký kůň Test", result["content"][0]["text"])
        result = self.call_tool(access, "search_read", model="ir.config_parameter")
        self.assertTrue(result["isError"])
        self.assertIn("propose_rule", names, "navrhnout pravidlo jde i ze spojení jen pro čtení")
        result = self.call_tool(access, "propose_rule", name="Kontakty", reason="test", models=["res.partner"],
                                operations=["write"])
        self.assertFalse(result.get("isError"), result)
        rule = self.env["mcp.rule"].search([("name", "=", "Kontakty")])
        self.assertEqual(rule.state, "proposed")
        self.assertIn(f"/odoo/action-mcp_oauth_server.action_mcp_rule/{rule.id}", result["content"][0]["text"])
        self.assertTrue(self.env["mcp.audit.log"].search_count([("tool", "=", "search_read"), ("status", "=", "denied")]))

    def test_write_after_consent(self):
        self.env["mcp.rule"].create({
            "name": "Kontakty", "perm_create": True, "perm_write": True,
            "extra_model_ids": [Command.set([self.env["ir.model"]._get("res.partner").id])],
        })
        _client_id, tokens = self.connect(allow_write=True)
        self.assertIn("odoo.write", tokens["scope"].split())
        names = {t["name"] for t in self.mcp(tokens["access_token"], "tools/list").json()["result"]["tools"]}
        self.assertIn("create_record", names)
        self.assertNotIn("delete_record", names)
        result = self.call_tool(tokens["access_token"], "create_record", model="res.partner",
                                values={"name": "Pivovar Test"})
        self.assertFalse(result.get("isError"), result)
        self.assertTrue(self.env["res.partner"].search_count([("name", "=", "Pivovar Test")]))

    def test_pkce_and_code_reuse(self):
        client_id = self.register().json()["client_id"]
        code = self.authorize(client_id)
        response = self.exchange(client_id, code, verifier="x" * 64)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")
        self.assertEqual(self.exchange(client_id, code).json()["error"], "invalid_grant", "kód jde použít jen jednou")

    def test_refresh_rotation_and_reuse(self):
        client_id, tokens = self.connect()
        refresh = lambda token: self.url_open("/api/mcp/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": token, "client_id": client_id})
        response = refresh(tokens["refresh_token"])
        self.assertEqual(response.status_code, 200, response.text)
        new_tokens = response.json()
        self.assertNotEqual(new_tokens["refresh_token"], tokens["refresh_token"])
        self.assertEqual(self.mcp(new_tokens["access_token"], "ping").status_code, 200)
        # starý refresh token po lhůtě = možná krádež, odvolat celé spojení
        old = self.env["mcp.oauth.token"]._find(tokens["refresh_token"], "refresh")
        old.used_date = fields.Datetime.now() - timedelta(minutes=5)
        response = refresh(tokens["refresh_token"])
        self.assertEqual(response.json()["error"], "invalid_grant")
        self.assertEqual(self.mcp(new_tokens["access_token"], "ping").status_code, 401)

    def test_revoke_from_preferences(self):
        _client_id, tokens = self.connect()
        grant = self.env["mcp.oauth.grant"].search([("user_id", "=", self.user.id)])
        grant.with_user(self.user).action_revoke()
        self.assertEqual(self.mcp(tokens["access_token"], "ping").status_code, 401)

    def test_consent_in_user_language(self):
        """Souhlas v jazyce uživatele, ne podle prohlížeče."""
        self.env["res.lang"]._activate_lang("cs_CZ")
        self.env["ir.module.module"]._load_module_terms(["mcp_oauth_server"], ["cs_CZ"])
        self.user.lang = "cs_CZ"
        client_id = self.register().json()["client_id"]
        self.authenticate(self.user.login, PASSWORD)
        page = self.url_open("/api/mcp/oauth/authorize?" + urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "scope": "odoo.read",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256"}), headers={"Accept-Language": "en-US"})
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("se chce připojit k Odoo", page.text)
        self.assertIn("Povolit", page.text)

    def test_cimd_client(self):
        client_id = "https://claude.ai/oauth/test-client-metadata"
        metadata = {"client_id": client_id, "client_name": "Claude", "redirect_uris": [REDIRECT]}
        with patch.object(oauth, "fetch_client_metadata", return_value=metadata):
            code = self.authorize(client_id)
            response = self.exchange(client_id, code)
        self.assertEqual(response.status_code, 200, response.text)
        self.authenticate(self.user.login, PASSWORD)
        page = self.url_open("/api/mcp/oauth/authorize?" + urlencode({
            "response_type": "code", "client_id": "https://evil.example/c.json", "redirect_uri": REDIRECT,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256"}))
        self.assertEqual(page.status_code, 400)
        self.assertIn("are not allowed", page.text)

    def test_api_key(self):
        keys = self.env["res.users.apikeys"].with_user(self.user)
        read_key = keys._generate("mcp", "Claude Code", None)
        rpc_key = keys._generate("rpc", "RPC", None)
        self.assertEqual(self.mcp(rpc_key, "ping").status_code, 401, "běžný API klíč do MCP nesmí")
        self.assertEqual(self.mcp(read_key, "ping").status_code, 200)
        whoami = json.loads(self.call_tool(read_key, "whoami")["content"][0]["text"])
        self.assertEqual(whoami["connection"]["auth"], "apikey")
        self.assertFalse(whoami["write_allowed"])

    def test_report_download(self):
        view = self.env["ir.ui.view"].create({
            "name": "mcp_test_report", "type": "qweb", "key": "mcp_oauth_server.test_report",
            "arch": '<t t-name="mcp_oauth_server.test_report"><t t-call="web.html_container">'
                    '<t t-foreach="docs" t-as="o"><p t-out="o.name"/></t></t></t>',
        })
        self.env["ir.actions.report"].create({
            "name": "Test kontaktu", "model": "res.partner", "report_type": "qweb-pdf",
            "report_name": view.key, "print_report_name": "'Kontakt %s' % object.name",
        })
        _client_id, tokens = self.connect()
        reports = json.loads(self.call_tool(tokens["access_token"], "list_reports", model="res.partner")["content"][0]["text"])
        self.assertIn("mcp_oauth_server.test_report", [r["report"] for r in reports["reports"]])
        result = self.call_tool(tokens["access_token"], "get_report", report="mcp_oauth_server.test_report",
                                ids=[self.partner.id])
        self.assertFalse(result.get("isError"), result)
        data = json.loads(result["content"][0]["text"])
        self.assertEqual(data["filename"], "Kontakt Žluťoučký kůň Test.pdf")
        path = urlsplit(data["download_url"]).path
        self.authenticate(None, None)
        response = self.url_open(path)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Žluťoučký kůň Test", response.text)
        self.assertEqual(self.url_open("/api/mcp/download/mcpd_neplatny").status_code, 404)
