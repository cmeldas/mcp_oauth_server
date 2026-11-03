# -*- coding: utf-8 -*-
"""Stažení PDF vytvořeného nástrojem get_report přes jednorázovou adresu (platí 15 minut)."""
import logging

from odoo import http
from odoo.http import request
from odoo.http.stream import content_disposition

from .common import MCP_PATH, NO_STORE

_logger = logging.getLogger(__name__)


class McpDownloadController(http.Controller):

    @http.route(MCP_PATH + "/download/<string:token>", type="http", auth="none", methods=["GET"],
                csrf=False, save_session=False, readonly=False, sitemap=False)
    def download(self, token, **_kwargs):
        download = request.env["mcp.download"].sudo()._find_valid(token)
        if not download:
            # jazyk podle prohlížeče (Accept-Language), jinak podle firmy
            message = request.env._("The link has expired or does not exist. Ask the AI client for a new one.")
            return request.make_response(message,
                                         headers=[("Content-Type", "text/plain; charset=utf-8"), *NO_STORE], status=404)
        download.download_count += 1
        _logger.info("MCP: file %s downloaded (user %s)", download.filename, download.user_id.login)
        return request.make_response(download.data.content, headers=[
            ("Content-Type", download.mimetype or "application/octet-stream"),
            ("Content-Disposition", content_disposition(download.filename)),
            ("X-Content-Type-Options", "nosniff"),
            *NO_STORE,
        ])
