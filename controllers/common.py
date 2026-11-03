# -*- coding: utf-8 -*-
"""Společné pro controllery: veřejná adresa serveru a odpovědi JSON."""
from odoo.http import request

from ..lib import oauth

MCP_PATH = "/api/mcp"
NO_STORE = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]
TRUSTED_ORIGIN_HOSTS = ("claude.ai", "claude.com", "chatgpt.com")


def base_url() -> str:
    """Veřejná adresa Odoo bez lomítka na konci, stejná jako adresa MCP zadaná v klientovi.

    1. parametr `mcp_oauth_server.base_url`;
    2. zamrzlé `web.base.url` (třeba `https://odoo.example.com`, i když proxy nepředá schéma);
    3. adresa z požadavku (s `proxy_mode` podle X-Forwarded-*).
    """
    params = request.env["ir.config_parameter"].sudo()
    configured = params.get_str("mcp_oauth_server.base_url")
    if not configured and params.get_str("web.base.url.freeze") in ("True", "true", "1"):
        configured = params.get_str("web.base.url")
    return (configured or request.httprequest.host_url).rstrip("/")


def resource_url() -> str:
    return base_url() + MCP_PATH


def resource_metadata_url() -> str:
    return base_url() + "/.well-known/oauth-protected-resource" + MCP_PATH


def json_response(data, status: int = 200, headers=None):
    return request.make_json_response(data, headers=list(headers or []), status=status)


def client_ip() -> str | None:
    return request.httprequest.remote_addr


def origin_allowed(origin: str | None) -> bool:
    """Prohlížeč posílá Origin; servery (claude.ai, ChatGPT) obvykle ne. Ochrana proti DNS rebindingu."""
    if not origin or origin == "null":
        return not origin
    host = oauth.host_of(origin)
    return (
        origin.rstrip("/") == base_url()
        or host in oauth.LOOPBACK_HOSTS
        or oauth.host_allowed(host, list(TRUSTED_ORIGIN_HOSTS))
    )


def cors_headers(origin: str | None) -> list:
    if not origin or not origin_allowed(origin):
        return []
    return [
        ("Access-Control-Allow-Origin", origin),
        ("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"),
        ("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id"),
        ("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id"),
        ("Access-Control-Max-Age", "600"),
        ("Vary", "Origin"),
    ]
