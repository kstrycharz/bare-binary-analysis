"""Rule pack integrity and the scanner.

The self-test here is the thing that keeps the rule pack honest: every rule
declares positive and negative fixtures, and they are executed. A rule that
does not match its own example is a rule that silently finds nothing, which is
the worst failure mode a scanner has — it looks like a clean artifact.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models.enums import Severity
from core.rules import (
    Rule,
    RuleLoadError,
    RulePack,
    load_rule_pack,
    mask,
    scan_bytes,
    shannon_entropy,
)
from core.rules.scanner import extract_ascii, extract_strings, extract_utf16le

RULES_DIR = Path(__file__).resolve().parents[2] / "detections"


@pytest.fixture(scope="module")
def pack() -> RulePack:
    return load_rule_pack(RULES_DIR)


class TestRulePackIntegrity:
    def test_pack_loads_with_rules(self, pack: RulePack) -> None:
        assert len(pack.enabled_rules()) >= 15

    def test_hash_is_stable_across_loads(self, pack: RulePack) -> None:
        """The pack hash goes into the run manifest and underwrites the
        determinism claim. If it varies between loads, the claim is void."""
        assert load_rule_pack(RULES_DIR).hash == pack.hash

    def test_rule_ids_are_unique(self, pack: RulePack) -> None:
        ids = [r.id for r in pack.rules]
        assert len(ids) == len(set(ids))

    def test_rules_are_returned_in_deterministic_order(self, pack: RulePack) -> None:
        ids = [r.id for r in pack.enabled_rules()]
        assert ids == sorted(ids)

    def test_every_rule_has_remediation(self, pack: RulePack) -> None:
        """A finding without a fix is a complaint. Remediation is not optional."""
        missing = [r.id for r in pack.enabled_rules() if len(r.remediation) < 40]
        assert missing == [], f"rules lacking substantive remediation: {missing}"

    def test_every_rule_has_a_description(self, pack: RulePack) -> None:
        missing = [r.id for r in pack.enabled_rules() if len(r.description) < 20]
        assert missing == []

    def test_credential_rules_carry_a_cwe(self, pack: RulePack) -> None:
        """SARIF consumers and compliance reports key off this."""
        missing = [
            r.id for r in pack.enabled_rules() if Severity(r.severity).blocks_release and not r.cwe
        ]
        assert missing == []


class TestRuleFixtures:
    """Every rule must match its positives and reject its negatives."""

    def test_every_rule_declares_fixtures(self, pack: RulePack) -> None:
        missing = [
            r.id for r in pack.enabled_rules() if not r.examples_positive or not r.examples_negative
        ]
        assert missing == [], f"rules without both fixtures: {missing}"

    def test_positive_fixtures_match(self, pack: RulePack) -> None:
        failures: list[str] = []
        for rule in pack.enabled_rules():
            for example in rule.examples_positive:
                matches = scan_bytes(example.encode(), _only(pack, rule.id))
                if not matches:
                    failures.append(f"{rule.id}: did not match {example!r}")
        assert failures == []

    def test_negative_fixtures_do_not_match(self, pack: RulePack) -> None:
        failures: list[str] = []
        for rule in pack.enabled_rules():
            for example in rule.examples_negative:
                matches = scan_bytes(example.encode(), _only(pack, rule.id))
                if matches:
                    failures.append(
                        f"{rule.id}: wrongly matched {example!r} -> {matches[0].value!r}"
                    )
        assert failures == []


def _only(pack: RulePack, rule_id: str) -> RulePack:
    """A pack containing one rule, so a fixture failure names that rule rather
    than being masked by another rule matching the same text."""
    rules = tuple(r for r in pack.rules if r.id == rule_id)
    return RulePack(
        version=pack.version, rules=rules, hash=pack.hash, false_positives=pack.false_positives
    )


class TestFalsePositiveCorpus:
    def test_aws_documentation_key_is_dropped(self, pack: RulePack) -> None:
        """The single most important false positive in the entire product. A
        scanner whose first finding is the AWS docs example is one nobody
        trusts."""
        matches = scan_bytes(b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", pack)
        assert [m for m in matches if m.rule_id == "aws-access-key-id"] == []

    def test_a_real_looking_key_is_not_dropped(self, pack: RulePack) -> None:
        matches = scan_bytes(b"aws_access_key_id = AKIA2E0A8F3B5C7D9E1F\n", pack)
        assert any(m.rule_id == "aws-access-key-id" for m in matches)

    @pytest.mark.parametrize("value", [b"127.0.0.1", b"192.168.1.1"])
    def test_common_default_addresses_are_dropped(self, pack: RulePack, value: bytes) -> None:
        matches = scan_bytes(value, pack)
        assert [m for m in matches if m.rule_id == "private-ip-address"] == []


class TestStringExtraction:
    def test_ascii_strings_carry_their_offset(self) -> None:
        data = b"\x00\x00hello world\x00\x00"
        found = list(extract_ascii(data))
        assert len(found) == 1
        assert found[0].value == "hello world"
        assert found[0].offset == 2

    def test_utf16le_strings_are_extracted(self) -> None:
        """Windows binaries keep a large share of their strings wide, and a
        scanner that only walks ASCII misses roughly half the secrets."""
        data = b"\x00\x00" + "secret_value".encode("utf-16le") + b"\x00\x00"
        found = list(extract_utf16le(data))
        assert any(s.value == "secret_value" for s in found)

    def test_utf16le_is_found_at_odd_alignment(self) -> None:
        """Wide strings in resource sections are not guaranteed to start on an
        even offset, and a single-alignment scan quietly misses those."""
        data = b"\xff" + "oddaligned_secret".encode("utf-16le") + b"\xff"
        assert any(s.value == "oddaligned_secret" for s in extract_utf16le(data))

    def test_extraction_order_is_deterministic(self) -> None:
        data = b"alpha_string\x00" + "beta_string".encode("utf-16le") + b"\x00gamma_string"
        first = [(s.offset, s.encoding, s.value) for s in extract_strings(data)]
        second = [(s.offset, s.encoding, s.value) for s in extract_strings(data)]
        assert first == second == sorted(first)

    def test_short_runs_are_ignored(self) -> None:
        assert list(extract_ascii(b"\x00ab\x00cd\x00")) == []


class TestScanning:
    def test_finds_a_secret_hidden_in_a_wide_string(self, pack: RulePack) -> None:
        """The headline capability: a key that ASCII-only tools miss entirely."""
        data = b"\x00" * 32 + "AKIA2E0A8F3B5C7D9E1F".encode("utf-16le") + b"\x00" * 32
        matches = [m for m in scan_bytes(data, pack) if m.rule_id == "aws-access-key-id"]

        assert len(matches) == 1
        assert matches[0].encoding == "utf-16le"
        assert matches[0].offset == 32

    def test_scan_results_are_deterministic(self, pack: RulePack) -> None:
        data = (
            b"AKIA2E0A8F3B5C7D9E1F\x00"
            + b"-----BEGIN RSA PRIVATE KEY-----\x00"
            + "C:\\build\\Project Hummingbird\\updater.pdb".encode("utf-16le")
        )
        first = [(m.rule_id, m.offset, m.value) for m in scan_bytes(data, pack)]
        second = [(m.rule_id, m.offset, m.value) for m in scan_bytes(data, pack)]
        assert first == second

    def test_value_hash_is_stable_and_independent_of_encoding(self, pack: RulePack) -> None:
        """The same secret in ASCII and in UTF-16 must dedupe to one finding."""
        ascii_hit = scan_bytes(b"AKIA2E0A8F3B5C7D9E1F", pack)[0]
        wide_hit = scan_bytes("AKIA2E0A8F3B5C7D9E1F".encode("utf-16le"), pack)[0]
        assert ascii_hit.value_hash == wide_hit.value_hash

    def test_context_never_contains_the_plaintext(self, pack: RulePack) -> None:
        """The context snippet is what gets sent to a remote model. If the
        secret survives in it, the entire trust boundary is void."""
        secret = "AKIA2E0A8F3B5C7D9E1F"
        data = f"config: aws_key={secret} region=us-east-1".encode()
        for match in scan_bytes(data, pack):
            assert secret not in match.context

    def test_plaintext_context_is_the_same_window_unmasked(self, pack: RulePack) -> None:
        """Only emitted under plaintext retention; it must be the masked window
        with the value put back, not a different slice of the file."""
        secret = "AKIA2E0A8F3B5C7D9E1F"
        data = f"config: aws_key={secret} region=us-east-1".encode()
        match = next(m for m in scan_bytes(data, pack) if m.rule_id == "aws-access-key-id")
        assert secret in match.context_plaintext
        assert match.context_plaintext.replace(secret, mask(secret)) == match.context


class TestMasking:
    def test_masking_keeps_the_shape_not_the_secret(self) -> None:
        masked = mask("sk_live_EXAMPLEONLYNOTAREALKEY00")
        assert masked.startswith("sk_l")
        assert masked.endswith("EY00")
        assert "EXAMPLEONLYNOTAREAL" not in masked

    def test_short_values_are_fully_masked(self) -> None:
        """Revealing 8 of 10 characters is not masking."""
        assert set(mask("hunter2xy")) == {"•"}


class TestEntropy:
    def test_random_scores_higher_than_english(self) -> None:
        assert shannon_entropy("9f8e7d6c5b4a39281706f5e4") > shannon_entropy("password")

    def test_empty_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0


class TestRejectsMatching:
    """The `rejects_matching` gate.

    Motivated by the field test: `scm-url` fired at *high* severity on
    `git://github.com/dotnet/runtime` inside a shipped .NET assembly and on a
    public GitHub API URL inside a Go binary. Both are ordinary build
    provenance pointing at a public mirror. A gate that blocks a release on
    those is a gate a team switches off, so the exclusion is load-bearing and
    gets its own tests rather than resting on the rule fixtures alone.
    """

    def test_public_forge_urls_are_rejected(self, pack: RulePack) -> None:
        observed = [
            b"git://github.com/dotnet/runtime",
            b"https://api.github.com/repos/syncthing/syncthing/releases?per_page=30",
            b"git+ssh://git@github.com/example/project.git",
            b"https://raw.githubusercontent.com/example/project/main/x.git",
        ]
        for sample in observed:
            matches = scan_bytes(sample, _only(pack, "scm-url"))
            assert matches == [], f"{sample!r} should not be an SCM disclosure"

    def test_credentialed_scm_hosts_still_match(self, pack: RulePack) -> None:
        """The exclusion must not hollow the rule out."""
        internal = [
            b"ssh://git@gitlab.internal.example.com:2222/firmware/bootloader.git",
            b"svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/B99133",
        ]
        for sample in internal:
            matches = scan_bytes(sample, _only(pack, "scm-url"))
            assert matches, f"{sample!r} is internal disclosure and must match"

    def test_unauthenticated_repo_urls_are_a_separate_low_rule(self, pack: RulePack) -> None:
        """The split that stops a citation blocking a release.

        `scm-url` is about hosts that expect credentials. An http(s) repository
        path is overwhelmingly a citation — license files and vendored sources
        are full of them — so it is reported at low severity by
        `scm-repository-reference` and never blocks a release on its own.
        """
        sample = b"https://git.corp.example.net/scm/platform/service.git"
        assert scan_bytes(sample, _only(pack, "scm-url")) == []
        assert scan_bytes(sample, _only(pack, "scm-repository-reference"))

    def test_vendored_third_party_urls_do_not_block(self, pack: RulePack) -> None:
        """Observed nine times at high on a shipped NVIDIA installer, from
        ffmpeg and v4l-utils homepages in a Chromium license file."""
        for sample in (
            b"https://git.ffmpeg.org/ffmpeg.git",
            b"http://marijnhaverbeke.nl/git/acorn",
            b"git://github.com/dotnet/runtime",
        ):
            blocking = scan_bytes(sample, _only(pack, "scm-url"))
            assert blocking == [], f"{sample!r} must not be a high-severity finding"

    def test_gate_is_applied_by_accepts(self) -> None:
        import re as _re

        rule = Rule(
            id="t",
            name="t",
            category="c",
            severity=Severity.HIGH,
            patterns=(),
            rejects_matching=(_re.compile(r"public\.example\.com"),),
        )
        assert rule.accepts("https://internal.example.com/repo") is True
        assert rule.accepts("https://public.example.com/repo") is False

    def test_a_bad_rejects_regex_is_fatal_at_load(self, tmp_path: Path) -> None:
        """Consistent with every other load error: a rule pack that silently
        drops a broken exclusion produces a scan that silently over-reports."""
        (tmp_path / "bad.yaml").write_text(
            "version: '1'\n"
            "rules:\n"
            "  - id: broken\n"
            "    name: Broken\n"
            "    category: c\n"
            "    severity: low\n"
            "    patterns:\n"
            "      - regex: 'abc'\n"
            "    rejects_matching:\n"
            "      - '([unclosed'\n",
            encoding="utf-8",
        )
        with pytest.raises(RuleLoadError, match="rejects_matching"):
            load_rule_pack(tmp_path)
