# -*- coding: utf-8 -*-
"""Stažení obrázku z veřejné adresy pro nástroj `set_image_from_url`.

Server tu stahuje adresu, kterou poslal AI klient, proto ochrana proti SSRF: jen http(s)
na portech 80 a 443, jen veřejné IP adresy (i po každém přesměrování), nejvýš 10 MB.
"""
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

from odoo.tools.translate import LazyTranslate

_lt = LazyTranslate(__name__)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 4
USER_AGENT = "Mozilla/5.0 (compatible; OdooMCP/1.0; +https://github.com/cmeldas/mcp_oauth_server)"

# (podpis na začátku souboru, typ)
IMAGE_SIGNATURES = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def sniff_image_type(data: bytes) -> str | None:
    """Typ obrázku podle obsahu; SVG záměrně ne (může obsahovat skripty)."""
    for signature, mimetype in IMAGE_SIGNATURES:
        if data.startswith(signature):
            return mimetype
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def check_public_host(hostname: str, port: int | None) -> None:
    """Všechny adresy, na které se jméno přeloží, musí být veřejné."""
    if not hostname:
        raise ValueError(_lt("The URL has no host name."))
    try:
        infos = socket.getaddrinfo(hostname, port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise ValueError(_lt("Server %s does not exist.", hostname)) from error
    for *_rest, sockaddr in infos:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global or address.is_multicast:
            raise ValueError(_lt("%(host)s leads to a non-public network (%(address)s).", host=hostname, address=str(address)))


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(_lt("Images can only be downloaded from http or https URLs."))
    if parts.username or parts.password:
        raise ValueError(_lt("The URL must not contain a user name and password."))
    if parts.port not in (None, 80, 443):
        raise ValueError(_lt("Images can only be downloaded from the standard ports 80 and 443."))
    check_public_host(parts.hostname, parts.port)


def fetch_image(url: str, timeout: float = 15.0) -> tuple[bytes, str, str]:
    """Vrátí (obsah, typ, konečná adresa). Při chybě ValueError se zprávou `_lt` (přeloží `i18n.error_text`)."""
    for _hop in range(MAX_REDIRECTS + 1):
        check_url(url)
        try:
            response = requests.get(
                url, timeout=(5, timeout), allow_redirects=False, stream=True,
                # JPEG a PNG Odoo zmenší na náhledy, WEBP uloží jen v původní velikosti
                headers={"User-Agent": USER_AGENT, "Accept": "image/jpeg,image/png;q=0.9,image/*;q=0.5"},
            )
        except requests.RequestException as error:
            raise ValueError(_lt("The download failed: %s", str(error))) from error
        with response:
            if response.is_redirect:
                url = urljoin(url, response.headers.get("Location", ""))
                continue
            if response.status_code >= 400:
                raise ValueError(_lt("The server returned error %s.", response.status_code))
            data = bytearray()
            for chunk in response.iter_content(64 * 1024):
                data += chunk
                if len(data) > MAX_IMAGE_BYTES:
                    raise ValueError(_lt("The image is larger than 10 MB."))
        mimetype = sniff_image_type(bytes(data))
        if not mimetype:
            declared = response.headers.get("Content-Type", "").split(";")[0].strip() or "?"
            raise ValueError(_lt("The URL does not point to a JPEG, PNG, GIF or WEBP image (%s).", declared))
        return bytes(data), mimetype, url
    raise ValueError(_lt("Too many redirects."))
