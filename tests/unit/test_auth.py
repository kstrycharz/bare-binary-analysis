"""API token minting, verification, and scope rules.

Split the way the code is: the pure functions here need no database, the
lifecycle tests run against a real schema in SQLite, and the endpoint-level
enforcement lives in `test_auth_api.py`. All three matter, because an
authentication bug that only shows up at one layer is indistinguishable from
having no authentication at all.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.auth import (
    TOKEN_PREFIX,
    Scope,
    generate_token,
    hash_token,
    looks_like_token,
    parse_bearer,
    redact,
    tokens_equal,
)
from core.models import ApiToken, AuditLog
from core.models.base import Base
from core.models.enums import AuditAction
from core.pipeline.tokens import (
    TokenError,
    create_token,
    ensure_bootstrap_token,
    list_tokens,
    revoke_token,
    verify_token,
)


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as active:
        yield active
    engine.dispose()


# --- the primitives -------------------------------------------------------


class TestTokenPrimitives:
    def test_tokens_are_unique_and_prefixed(self) -> None:
        tokens = {generate_token() for _ in range(200)}
        assert len(tokens) == 200
        assert all(t.startswith(TOKEN_PREFIX) for t in tokens)

    def test_tokens_are_long_enough_to_be_unguessable(self) -> None:
        token = generate_token()
        assert len(token) - len(TOKEN_PREFIX) >= 40

    def test_hash_is_stable_and_not_the_token(self) -> None:
        token = generate_token()
        assert hash_token(token) == hash_token(token)
        assert token not in hash_token(token)
        assert len(hash_token(token)) == 64

    def test_hash_ignores_surrounding_whitespace(self) -> None:
        """CI systems love to add a trailing newline to a secret."""
        token = generate_token()
        assert hash_token(f"  {token}\n") == hash_token(token)

    def test_distinct_tokens_hash_differently(self) -> None:
        assert hash_token(generate_token()) != hash_token(generate_token())

    def test_tokens_equal_is_constant_time_comparison(self) -> None:
        assert tokens_equal("abc", "abc") is True
        assert tokens_equal("abc", "abd") is False

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("Bearer bare_abc", "bare_abc"),
            ("bearer bare_abc", "bare_abc"),
            ("BEARER  bare_abc  ", "bare_abc"),
            ("bare_abc", "bare_abc"),  # bare token: proxies mangle the scheme
            ("", None),
            ("   ", None),
            (None, None),
            ("Bearer ", None),
        ],
    )
    def test_parse_bearer(self, header: str | None, expected: str | None) -> None:
        assert parse_bearer(header) == expected

    def test_redact_never_reveals_the_secret(self) -> None:
        token = generate_token()
        shown = redact(token)
        assert token not in shown
        assert shown.startswith(TOKEN_PREFIX)
        # Eight characters is enough to match a log line, far too few to guess.
        assert len(shown) <= len(TOKEN_PREFIX) + 9

    def test_looks_like_token(self) -> None:
        assert looks_like_token(generate_token()) is True
        assert looks_like_token("hunter2") is False
        assert looks_like_token(f"{TOKEN_PREFIX}short") is False


class TestScopes:
    def test_admin_satisfies_everything(self) -> None:
        assert Scope.ADMIN.satisfies(Scope.CI)
        assert Scope.ADMIN.satisfies(Scope.ADMIN)

    def test_ci_cannot_reach_admin(self) -> None:
        """The one boundary that matters: a build agent may submit and be told
        a verdict, but may not read the findings corpus (ADR-0019)."""
        assert Scope.CI.satisfies(Scope.CI)
        assert not Scope.CI.satisfies(Scope.ADMIN)


# --- lifecycle against a real schema --------------------------------------


class TestTokenLifecycle:
    def test_created_token_verifies(self, session: Session) -> None:
        minted = create_token(session, name="ci", scope=Scope.CI)
        record = verify_token(session, minted.token)
        assert record is not None
        assert record.name == "ci"
        assert record.scope == "ci"

    def test_plaintext_is_never_stored(self, session: Session) -> None:
        minted = create_token(session, name="ci")
        stored = session.get(ApiToken, minted.record_id)
        assert stored is not None
        assert minted.token not in (stored.token_hash, stored.token_prefix, stored.name)
        assert stored.token_hash == hash_token(minted.token)

    def test_unknown_token_is_rejected(self, session: Session) -> None:
        create_token(session, name="ci")
        assert verify_token(session, generate_token()) is None

    def test_empty_token_is_rejected(self, session: Session) -> None:
        assert verify_token(session, "") is None

    def test_revoked_token_stops_working(self, session: Session) -> None:
        minted = create_token(session, name="ci")
        assert verify_token(session, minted.token) is not None
        revoke_token(session, "ci")
        assert verify_token(session, minted.token) is None

    def test_revocation_keeps_the_row_for_the_audit_trail(self, session: Session) -> None:
        minted = create_token(session, name="ci")
        revoke_token(session, "ci")
        stored = session.get(ApiToken, minted.record_id)
        assert stored is not None
        assert stored.revoked_at is not None

    def test_expired_token_stops_working(self, session: Session) -> None:
        minted = create_token(session, name="ci", expires_in_days=1)
        record = session.get(ApiToken, minted.record_id)
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.flush()
        assert verify_token(session, minted.token) is None

    def test_token_valid_until_its_expiry(self, session: Session) -> None:
        minted = create_token(session, name="ci", expires_in_days=30)
        assert verify_token(session, minted.token) is not None

    def test_duplicate_active_name_is_refused(self, session: Session) -> None:
        """Two live credentials with one name cannot be rotated safely."""
        create_token(session, name="ci")
        with pytest.raises(TokenError, match="already exists"):
            create_token(session, name="ci")

    def test_name_can_be_reused_after_revocation(self, session: Session) -> None:
        create_token(session, name="ci")
        revoke_token(session, "ci")
        assert create_token(session, name="ci") is not None

    def test_unnamed_token_is_refused(self, session: Session) -> None:
        with pytest.raises(TokenError, match="name"):
            create_token(session, name="   ")

    def test_negative_expiry_is_refused(self, session: Session) -> None:
        with pytest.raises(TokenError, match="positive"):
            create_token(session, name="ci", expires_in_days=-5)

    def test_revoking_an_unknown_token_is_an_error(self, session: Session) -> None:
        with pytest.raises(TokenError, match="no active token"):
            revoke_token(session, "nope")

    def test_double_revocation_is_an_error(self, session: Session) -> None:
        create_token(session, name="ci")
        revoke_token(session, "ci")
        with pytest.raises(TokenError, match="already revoked"):
            revoke_token(session, "ci")

    def test_usage_is_tracked(self, session: Session) -> None:
        minted = create_token(session, name="ci")
        verify_token(session, minted.token)
        verify_token(session, minted.token)
        record = session.get(ApiToken, minted.record_id)
        assert record is not None
        assert record.use_count == 2
        assert record.last_used_at is not None

    def test_listing_hides_revoked_by_default(self, session: Session) -> None:
        create_token(session, name="live")
        create_token(session, name="dead")
        revoke_token(session, "dead")
        assert [t.name for t in list_tokens(session)] == ["live"]
        assert len(list_tokens(session, include_revoked=True)) == 2


class TestAuditTrail:
    def test_creation_is_audited(self, session: Session) -> None:
        create_token(session, name="ci", created_by="kyle")
        entries = session.query(AuditLog).filter_by(action=AuditAction.TOKEN_CREATED).all()
        assert len(entries) == 1
        assert entries[0].actor == "kyle"
        assert entries[0].detail["token_name"] == "ci"

    def test_audit_never_records_the_secret(self, session: Session) -> None:
        minted = create_token(session, name="ci")
        for entry in session.query(AuditLog).all():
            assert minted.token not in str(entry.detail)

    def test_revocation_is_audited(self, session: Session) -> None:
        create_token(session, name="ci")
        revoke_token(session, "ci", actor="kyle")
        entries = session.query(AuditLog).filter_by(action=AuditAction.TOKEN_REVOKED).all()
        assert len(entries) == 1
        assert entries[0].actor == "kyle"


class TestBootstrap:
    def test_first_start_mints_an_admin_token(self, session: Session) -> None:
        minted = ensure_bootstrap_token(session)
        assert minted is not None
        assert minted.scope is Scope.ADMIN
        assert verify_token(session, minted.token) is not None

    def test_bootstrap_is_idempotent(self, session: Session) -> None:
        """Restarting the API must not mint a new credential every time."""
        assert ensure_bootstrap_token(session) is not None
        assert ensure_bootstrap_token(session) is None

    def test_bootstrap_skipped_when_any_token_exists(self, session: Session) -> None:
        create_token(session, name="ci", scope=Scope.CI)
        assert ensure_bootstrap_token(session) is None

    def test_bootstrap_not_reissued_after_revocation(self, session: Session) -> None:
        """A revoked row still counts as 'tokens exist'. Otherwise revoking the
        last token would silently hand out a fresh admin credential on the next
        restart, which is a privilege-escalation path, not a convenience."""
        minted = ensure_bootstrap_token(session)
        assert minted is not None
        revoke_token(session, "bootstrap")
        assert ensure_bootstrap_token(session) is None


class TestNoPlaintextInLogs:
    """The plaintext is disclosed once, on the console. Not into the log
    pipeline, where it would be shipped, indexed, and retained — which is the
    exact failure this product exists to find in other people's artifacts."""

    def test_bootstrap_does_not_log_the_token(
        self, session: Session, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        with caplog.at_level(logging.DEBUG):
            minted = ensure_bootstrap_token(session)
        assert minted is not None
        assert minted.token not in caplog.text

    def test_create_does_not_log_the_token(
        self, session: Session, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        with caplog.at_level(logging.DEBUG):
            minted = create_token(session, name="ci")
        assert minted.token not in caplog.text
