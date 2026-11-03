# -*- coding: utf-8 -*-
import base64
import hashlib

from odoo.tests import BaseCase, tagged

from ..lib import oauth, safe_fetch


@tagged("post_install", "-at_install")
class TestOAuthHelpers(BaseCase):

    def test_pkce(self):
        verifier = "a" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertTrue(oauth.pkce_matches(verifier, challenge))
        self.assertFalse(oauth.pkce_matches("b" * 43, challenge))
        self.assertFalse(oauth.pkce_matches("short", challenge), "verifier musí mít 43 až 128 znaků")
        self.assertFalse(oauth.pkce_matches(None, challenge))

    def test_loopback_redirect_ignores_port(self):
        registered = ["http://localhost/callback", "http://127.0.0.1/callback", "https://claude.ai/api/mcp/auth_callback"]
        self.assertTrue(oauth.redirect_matches("http://localhost:3118/callback", registered))
        self.assertTrue(oauth.redirect_matches("http://127.0.0.1:55001/callback", registered))
        self.assertTrue(oauth.redirect_matches("https://claude.ai/api/mcp/auth_callback", registered))
        self.assertFalse(oauth.redirect_matches("http://localhost:3118/other", registered))
        self.assertFalse(oauth.redirect_matches("https://claude.ai/api/mcp/auth_callback?x=1", registered))
        self.assertFalse(oauth.redirect_matches("http://evil.example:3118/callback", registered))

    def test_redirect_allowed_for_dcr(self):
        patterns = ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector/oauth/*"]
        self.assertTrue(oauth.redirect_allowed("https://claude.ai/api/mcp/auth_callback", patterns))
        self.assertTrue(oauth.redirect_allowed("https://chatgpt.com/connector/oauth/abc123", patterns))
        self.assertTrue(oauth.redirect_allowed("http://127.0.0.1:9000/cb", patterns))
        self.assertFalse(oauth.redirect_allowed("https://evil.example/cb", patterns))
        self.assertFalse(oauth.redirect_allowed("http://claude.ai/api/mcp/auth_callback", patterns))
        self.assertFalse(oauth.redirect_allowed("https://claude.ai/api/mcp/auth_callback#x", patterns))

    def test_scope_and_cimd_helpers(self):
        self.assertEqual(oauth.parse_scope("openid odoo.write odoo.read"), ["odoo.read", "odoo.write"])
        self.assertTrue(oauth.is_cimd_client_id("https://claude.ai/oauth/claude-code-client-metadata"))
        self.assertFalse(oauth.is_cimd_client_id("https://claude.ai/"))
        self.assertFalse(oauth.is_cimd_client_id("mcp-abc"))
        self.assertTrue(oauth.host_allowed("claude.ai", ["claude.ai"]))
        self.assertTrue(oauth.host_allowed("eu.claude.ai", ["claude.ai"]))
        self.assertFalse(oauth.host_allowed("evilclaude.ai", ["claude.ai"]))
        self.assertEqual(oauth.add_query("https://x.cz/cb?a=1", {"code": "c", "state": None}), "https://x.cz/cb?a=1&code=c")
        self.assertEqual(oauth.bearer_token("Bearer abc"), "abc")
        self.assertIsNone(oauth.bearer_token("Basic abc"))

    def test_safe_fetch_rejects_private_addresses(self):
        for url in ("http://127.0.0.1/a.png", "http://localhost/a.png", "http://10.0.0.1/a.png",
                    "http://192.168.1.10:8069/web/image", "file:///etc/passwd", "ftp://example.com/a.png",
                    "http://user:pass@example.com/a.png", "https://example.com:8443/a.png"):
            with self.assertRaises(ValueError, msg=url):
                safe_fetch.check_url(url)

    def test_sniff_image(self):
        self.assertEqual(safe_fetch.sniff_image_type(b"\x89PNG\r\n\x1a\n...."), "image/png")
        self.assertEqual(safe_fetch.sniff_image_type(b"\xff\xd8\xff\xe0...."), "image/jpeg")
        self.assertEqual(safe_fetch.sniff_image_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp")
        self.assertIsNone(safe_fetch.sniff_image_type(b"<svg xmlns='http://www.w3.org/2000/svg'/>"))
