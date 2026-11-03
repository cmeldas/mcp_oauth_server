# -*- coding: utf-8 -*-
{
    "name": "MCP Server with OAuth",
    "summary": "MCP server for Claude and other AI clients: OAuth 2.1 built into Odoo, read-only by default, "
               "writing per app and field",
    "description": """
MCP Server with OAuth
=====================

Remote MCP server (Streamable HTTP) at ``/api/mcp`` that Claude (claude.ai, desktop,
mobile, Claude Code) connects to as a custom connector. Odoo is also the OAuth 2.1
server: the user logs in with a normal Odoo account and confirms a consent page, no keys
are copied around. Claude Code can also use an API key with an MCP scope.

* **Read-only** by default: tools run as the logged-in user, so their Odoo access rights
  apply. Administrator rights (Settings, Access Rights) do not apply via MCP, sensitive
  fields (passwords, tokens, certificates) are always hidden.
* **Writing** is allowed by rules per app (Access Rights rows of the user), optionally
  only for listed fields, records matching a domain and selected actions. The AI client
  can propose a rule itself, but it applies only after manual approval in Odoo.
* **AI instructions** per company: how the system introduces itself, what it is and the
  company rules; the AI gets them right when connecting.
* **Tools** can be disabled or allowed only for selected people and groups. Other addons
  add their own tools by inheriting `mcp.tool` (method `_mcp_extra_tools`).
* **Draft replies:** the AI prepares a reply in the chatter (ticket, task…), the user
  reviews, edits and sends it. It is never sent automatically.
* **Reports** (invoices and other PDFs) as a download link valid for 15 minutes.
* **Audit** of all calls.
* Texts in **English and Czech**, following the language of the user.
""",
    "version": "20.0.1.0.1",
    "category": "Productivity",
    "author": "Matouš Čmelík",
    "website": "https://github.com/cmeldas/mcp_oauth_server",
    "license": "LGPL-3",
    "depends": ["base", "web", "mail"],
    "external_dependencies": {"python": ["requests"]},
    "data": [
        "security/ir.access.csv",
        "views/mcp_rule_views.xml",
        "views/mcp_oauth_views.xml",
        "views/mcp_audit_log_views.xml",
        "views/ir_model_fields_views.xml",
        "views/res_users_views.xml",
        "views/mcp_tool_views.xml",
        "views/oauth_templates.xml",
        "views/menus.xml",
    ],
    "assets": {
        "web.assets_backend": [
            "mcp_oauth_server/static/src/chatter/scheduled_message.xml",
        ],
    },
    "installable": True,
    "application": False,
    "auto_install": False,
}
