"""The contributor-login identity provider seam and the one value the service reads from it.

Specification section 8: a dedicated GitHub App's user authorization with
state and PKCE, a server-side code exchange, authenticated `GET /user`, and
the immutable numeric user id that call returns. A login name, an email, a
pasted personal token or an installation token is never the identity. The
adapter owns the exchange and discards the provider token before it returns;
the service receives only the `GET /user` body and reads its `id`.

No live adapter ships in this packet. Production startup refuses before one
could be wired (see `api.app.production_refusals`), and a live adapter holds its
client secret as a `SecretReference`, resolved at exchange time.
"""

import json
import re

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import MAX_BIGINT


CODE = re.compile(r"[A-Za-z0-9._~-]{1,256}")
MAX_USER_DOCUMENT = 65_536
MAX_AUTHORIZATION_URL = 2048


class IdentityProvider:
    """What the login flow needs from the provider; an adapter overrides both methods.

    `authorization_url(state, code_challenge)` returns the provider URL a
    browser visits, carrying the fixed callback, the state and the S256 PKCE
    challenge. `user_document(code, code_verifier)` exchanges the code with the
    verifier server-side, calls authenticated `GET /user`, discards the user
    token and returns that response body as bytes. Either may raise; every
    exception is a refused login.
    """

    def authorization_url(self, state, code_challenge):
        raise NotImplementedError

    def user_document(self, code, code_verifier):
        raise NotImplementedError


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _refuse_number(_value):
    raise ValueError("non-integer number")


def numeric_identity(document):
    """Return the positive integer `id` of one `GET /user` body, or refuse.

    Duplicate keys, a non-integer or boolean id, a missing id and anything
    other than a bounded UTF-8 JSON object refuse. No other field is read.
    """
    if type(document) is not bytes or not 0 < len(document) <= MAX_USER_DOCUMENT:
        raise AuthRefusal("auth_required", "identity-malformed")
    try:
        value = json.loads(document.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_float=_refuse_number, parse_constant=_refuse_number)
    except (UnicodeError, ValueError, RecursionError):
        raise AuthRefusal("auth_required", "identity-malformed") from None
    if type(value) is not dict:
        raise AuthRefusal("auth_required", "identity-malformed")
    identity = value.get("id")
    if type(identity) is not int or not 1 <= identity <= MAX_BIGINT:
        raise AuthRefusal("auth_required", "identity-malformed")
    return identity


def authorization_url(provider, state, code_challenge):
    """The provider's URL, refused unless it is a bounded HTTPS string."""
    try:
        url = provider.authorization_url(state, code_challenge)
    except Exception:
        raise AuthRefusal("authority_unavailable", "provider-unavailable") from None
    if (type(url) is not str or not url.startswith("https://") or len(url) > MAX_AUTHORIZATION_URL
            or not url.isascii() or any(character in url for character in "\r\n\t ")):
        raise AuthRefusal("authority_unavailable", "provider-unavailable")
    return url


def identify(provider, code, code_verifier):
    """Exchange one callback code through the adapter; any failure is a refused login."""
    if type(code) is not str or CODE.fullmatch(code) is None:
        raise AuthRefusal("request_invalid", "login-code-malformed")
    try:
        document = provider.user_document(code, code_verifier)
    except Exception:
        raise AuthRefusal("auth_required", "provider-refused") from None
    return numeric_identity(document)
