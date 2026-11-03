# -*- coding: utf-8 -*-
"""OAuth 2.1 bez ORM: tokeny, PKCE, adresy přesměrování, Client ID Metadata Document.

Odkazy: OAuth 2.1 (draft-ietf-oauth-v2-1), RFC 7636 (PKCE), RFC 8252 (loopback u nativních
aplikací), RFC 7591 (DCR), RFC 9207 (`iss` v odpovědi), draft-ietf-oauth-client-id-metadata-document.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import requests

from odoo.tools.translate import LazyTranslate

from .i18n import in_english, localize

_lt = LazyTranslate(__name__)

SCOPE_READ = "odoo.read"
SCOPE_WRITE = "odoo.write"
SCOPE_OFFLINE = "offline_access"
SUPPORTED_SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_OFFLINE)

ACCESS_PREFIX = "mcpa_"
REFRESH_PREFIX = "mcpr_"
CODE_PREFIX = "mcpc_"
DOWNLOAD_PREFIX = "mcpd_"

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
CIMD_MAX_BYTES = 64 * 1024
PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


class OAuthError(Exception):
    """Chyba podle RFC 6749 kap. 5.2: `error` je kód pro klienta, `description` text pro člověka.

    Klient dostane popis anglicky (RFC dovoluje v `error_description` jen ASCII), stránka chyby
    v prohlížeči ho ukáže v jazyce uživatele (`description_for`).
    """

    def __init__(self, error: str, description="", status: int = 400):
        super().__init__(in_english(description) or error)
        self.error = error
        self.description = description
        self.status = status

    def description_for(self, env) -> str:
        return str(localize(env, self.description) or self.error)

    def as_dict(self) -> dict:
        text = in_english(self.description)
        return {"error": self.error, **({"error_description": text} if text else {})}


def new_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def token_hash(secret_key: str, token: str) -> str:
    """Tokeny jsou náhodné 256bitové, stačí HMAC-SHA256 s tajemstvím databáze (ne pbkdf2)."""
    return hmac.new(secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


def pkce_matches(verifier: str | None, challenge: str | None) -> bool:
    """PKCE S256: BASE64URL(SHA256(code_verifier)) == code_challenge."""
    if not verifier or not challenge or not PKCE_VERIFIER.match(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


def parse_scope(scope: str | None) -> list[str]:
    """Známé scope v pevném pořadí, neznámé (třeba `openid`) se tiše vynechají."""
    requested = set((scope or "").split())
    return [s for s in SUPPORTED_SCOPES if s in requested]


def is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def redirect_matches(requested: str, registered: list[str]) -> bool:
    """Přesná shoda s registrovanou adresou; u loopbacku (RFC 8252 kap. 7.3) bez ohledu na port.

    Claude Code má v CIMD `http://localhost/callback` a `http://127.0.0.1/callback`,
    přesměruje ale na náhodný port, třeba `http://localhost:3118/callback`.
    """
    if not requested:
        return False
    if requested in registered:
        return True
    if not is_loopback(requested):
        return False
    req = urlsplit(requested)
    return any(
        is_loopback(uri)
        and urlsplit(uri).hostname == req.hostname
        and urlsplit(uri).path == req.path
        and urlsplit(uri).query == req.query
        for uri in registered
    )


def redirect_allowed(uri: str, patterns: list[str]) -> bool:
    """Smí se adresa zaregistrovat přes DCR? Loopback ano, jinak jen HTTPS podle seznamu.

    Vzor končící `*` je prefix (`https://chatgpt.com/connector/oauth/*`).
    """
    parts = urlsplit(uri or "")
    if parts.fragment or not parts.hostname:
        return False
    if is_loopback(uri):
        return True
    if parts.scheme != "https":
        return False
    return any(uri.startswith(p[:-1]) if p.endswith("*") else uri == p for p in patterns)


def add_query(uri: str, params: dict) -> str:
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(key, value) for key, value in params.items() if value not in (None, "")]
    return urlunsplit(parts._replace(query=urlencode(query)))


def host_of(uri: str) -> str:
    return urlsplit(uri or "").hostname or ""


def is_cimd_client_id(client_id: str) -> bool:
    """Client ID jako HTTPS adresa s cestou = Client ID Metadata Document."""
    parts = urlsplit(client_id or "")
    return parts.scheme == "https" and bool(parts.hostname) and parts.path not in ("", "/")


def host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in allowed_hosts)


def fetch_client_metadata(client_id: str, timeout: float = 5.0) -> dict:
    """Stáhne a ověří CIMD. Volat jen pro domény ze seznamu povolených (ochrana proti SSRF)."""
    try:
        response = requests.get(
            client_id, timeout=timeout, allow_redirects=False, stream=True,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        body = response.raw.read(CIMD_MAX_BYTES + 1, decode_content=True)
    except requests.RequestException as error:
        raise OAuthError("invalid_client", _lt("The client metadata document %(url)s could not be downloaded: %(error)s",
                                               url=client_id, error=str(error))) from error
    if len(body) > CIMD_MAX_BYTES:
        raise OAuthError("invalid_client", _lt("The client metadata document is larger than 64 kB."))
    try:
        data = json.loads(body)
    except ValueError as error:
        raise OAuthError("invalid_client", _lt("The client metadata document is not valid JSON.")) from error
    if not isinstance(data, dict) or data.get("client_id") != client_id:
        raise OAuthError("invalid_client", _lt("The client_id in the client metadata document does not match its URL."))
    redirect_uris = data.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris):
        raise OAuthError("invalid_client", _lt("The client metadata document has no redirect_uris."))
    return data


def bearer_token(header: str | None) -> str | None:
    match = re.match(r"^\s*bearer\s+(\S+)\s*$", header or "", re.IGNORECASE)
    return match.group(1) if match else None


def basic_credentials(header: str | None) -> tuple[str, str] | None:
    """client_secret_basic (RFC 6749 kap. 2.3.1)."""
    match = re.match(r"^\s*basic\s+(\S+)\s*$", header or "", re.IGNORECASE)
    if not match:
        return None
    try:
        decoded = base64.b64decode(match.group(1)).decode()
    except ValueError:
        return None
    client_id, _sep, secret = decoded.partition(":")
    return unquote(client_id), unquote(secret)


def www_authenticate(resource_metadata: str, scope: str | None = None, error: str | None = None,
                     description: str | None = None) -> str:
    params = [f'resource_metadata="{resource_metadata}"']
    if scope:
        params.append(f'scope="{scope}"')
    if error:
        params.append(f'error="{error}"')
    if description:
        params.append('error_description="{}"'.format(description.replace('"', "'")))
    return "Bearer " + ", ".join(params)
