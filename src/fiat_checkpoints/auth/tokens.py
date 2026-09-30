"""Opaque service secrets: 32 random bytes, shown once, stored only as SHA-256.

A session secret, a login state, a login binding and an access token are each
one of these. A presented value that is not exactly this shape is refused
before any lookup, so a provider token, a personal token or a login name never
reaches a query. The CSRF token is derived from the session secret, so it
needs neither storage nor a server key, and it reveals nothing about the
secret it came from.
"""

import base64
import hashlib
import hmac
import re
import secrets


SECRET = re.compile(r"[A-Za-z0-9_-]{43}")
CSRF_CONTEXT = b"fiat-checkpoints/csrf/v1\x00"
PKCE_CONTEXT = b"fiat-checkpoints/pkce/v1\x00"


def new_secret():
    return secrets.token_urlsafe(32)


def well_formed(value):
    return type(value) is str and SECRET.fullmatch(value) is not None


def secret_sha256(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _derive(context, *parts):
    raw = hashlib.sha256(context + b"\x00".join(part.encode("ascii") for part in parts)).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def csrf_token(session_secret):
    return _derive(CSRF_CONTEXT, session_secret)


def csrf_matches(session_secret, presented):
    return well_formed(presented) and hmac.compare_digest(csrf_token(session_secret), presented)


def pkce_verifier(state, binding):
    """The login's PKCE verifier, recomputed at the callback from its state and browser binding."""
    return _derive(PKCE_CONTEXT, state, binding)


def pkce_challenge(verifier):
    """RFC 7636 `S256`: unpadded base64url of SHA-256 over the verifier's ASCII bytes."""
    raw = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
