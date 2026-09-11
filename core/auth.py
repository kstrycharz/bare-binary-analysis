"""API tokens: minting, hashing, and scope checks.

Dependency-light on purpose — stdlib only — so the token logic can be tested
and reasoned about without a database or a web framework in the way.

**Why SHA-256 and not bcrypt/argon2.** Password hashes are slow because
passwords are low-entropy and guessable. These tokens are 256 bits from
``secrets.token_urlsafe``; there is no dictionary to attack and no user-chosen
weak input, so a slow KDF would buy nothing and cost a round trip on every
request. What matters instead is that the plaintext is never stored, the
comparison is constant-time, and the lookup is by hash so a leaked database
does not yield usable tokens.

**Why scopes exist at all.** ADR-0019 says findings do not travel to CI: a
findings list is a company's exposed secrets in one document. A build agent
needs to submit an artifact and read a verdict; it has no business reading the
corpus. That distinction is only real if the token enforces it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from enum import StrEnum

# A visible prefix so a leaked token is greppable in logs and recognisable in a
# secret scanner — including this one. It is not a security control; it is an
# incident-response affordance.
TOKEN_PREFIX = "bare_"

# 32 bytes of urlsafe base64. Long enough that brute force is not a threat
# model, short enough to paste into a CI secret field.
TOKEN_ENTROPY_BYTES = 32


class Scope(StrEnum):
    """What a token may do.

    Deliberately coarse. Fine-grained permissions on a two-actor system (a
    build agent and a human operator) are configuration nobody maintains
    correctly, and the meaningful boundary here is exactly one line: may this
    caller read the findings corpus, or only submit to it and receive a
    verdict?
    """

    CI = "ci"
    """Submit artifacts, poll run status, request a gate verdict, fetch SARIF.
    Cannot list findings, read artifact bytes, change a finding's status, or
    reveal plaintext."""

    ADMIN = "admin"
    """Everything, including the findings corpus and settings. What the
    dashboard and a human operator use."""

    @property
    def rank(self) -> int:
        return {Scope.CI: 0, Scope.ADMIN: 1}[self]

    def satisfies(self, required: Scope) -> bool:
        """Whether a token with this scope may perform a ``required`` action."""
        return self.rank >= required.rank


def generate_token() -> str:
    """A fresh token. Returned once, never stored, never recoverable."""
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)}"


def hash_token(token: str) -> str:
    """The stored form. Lookup is by this value, so it is indexed."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    """Constant-time comparison.

    Only reached on the static-token path; the database path compares hashes
    via an indexed lookup, which does not leak timing about the secret itself.
    """
    return hmac.compare_digest(left, right)


def parse_bearer(header_value: str | None) -> str | None:
    """Extract a token from an ``Authorization`` header.

    Accepts a bare token as well as ``Bearer <token>``: CI systems mangle
    header construction often enough that refusing the bare form buys nothing
    but support tickets, and the token is equally secret either way.
    """
    if not header_value:
        return None
    value = header_value.strip()
    if not value:
        return None

    # Split rather than slice a prefix: a header of exactly "Bearer" would
    # otherwise yield the literal string "Bearer" as the presented credential,
    # which then fails verification and lands "Bearer" in the audit log as if
    # someone had tried it as a token.
    parts = value.split(None, 1)
    if len(parts) == 2:
        if parts[0].lower() != "bearer":
            return None
        return parts[1].strip() or None
    if parts[0].lower() == "bearer":
        return None
    return parts[0] or None


def looks_like_token(value: str) -> bool:
    """Whether a string has the shape this system mints.

    Used to keep a malformed header out of the audit log's ``token_prefix``
    field, not as a validity check — a well-formed unknown token still fails.
    """
    return value.startswith(TOKEN_PREFIX) and len(value) > len(TOKEN_PREFIX) + 16


def redact(token: str) -> str:
    """A stable, non-reversible label for logs and audit rows.

    The first eight characters after the prefix are enough for an operator to
    match a log line to the token row they are looking at, and far too few to
    reconstruct the secret.
    """
    if not token:
        return "<empty>"
    body = token[len(TOKEN_PREFIX) :] if token.startswith(TOKEN_PREFIX) else token
    return f"{TOKEN_PREFIX}{body[:8]}…"
