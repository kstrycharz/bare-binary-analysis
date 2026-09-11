"""The `bare scan` command, end to end over real HTTP.

Drives the actual CLI against a stub server on localhost: real multipart
upload, real polling, real gate response, real exit code. Mocking the client
here would skip the two things most likely to break — the hand-rolled
multipart body and the exit code the pipeline reads — so it is not mocked.

No Docker and no database, so this belongs in the unit lane per §8.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.main import app

RUNNER = CliRunner()

# Mutable state the stub reads, so each test can shape the server's answers
# without standing up a new one.
STATE: dict[str, object] = {}


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep the test output clean
        return

    def _respond(self, code: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if self.path == "/api/runs":
            STATE["upload_body"] = body
            STATE["upload_content_type"] = self.headers.get("Content-Type", "")
            self._respond(
                201,
                {
                    "run_id": "run-1",
                    "artifact_name": "installer.exe",
                    "artifact_sha256": "a" * 64,
                    "size_bytes": len(body),
                    "status": "queued",
                },
            )
            return

        if self.path.endswith("/gate"):
            STATE["gate_request"] = json.loads(body or b"{}")
            self._respond(200, STATE.get("gate_response", {}))
            return

        self._respond(404, {"detail": "not found"})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        if self.path.endswith("/sarif"):
            self._respond(200, {"version": "2.1.0", "runs": []})
            return
        if self.path.startswith("/api/runs/"):
            self._respond(200, {"id": "run-1", "status": STATE.get("run_status", "completed")})
            return
        self._respond(404, {"detail": "not found"})


@pytest.fixture
def server() -> Iterator[str]:
    STATE.clear()
    STATE["run_status"] = "completed"
    STATE["gate_response"] = _gate_payload("pass", 0)

    httpd = HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _gate_payload(decision: str, exit_code: int, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "decision": decision,
        "exit_code": exit_code,
        "policy_name": "default",
        "run_id": "run-1",
        "baseline": "previous_run",
        "total_findings": 0,
        "counts_by_severity": {},
        "new_counts_by_severity": {},
        "degraded_stages": [],
        "warnings": [],
        "violations": [],
        "waived": [],
        "inherited": [],
    }
    payload.update(extra)
    return payload


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "installer.exe"
    path.write_bytes(b"MZ\x90\x00" + b"payload" * 500)
    return path


def _invoke(artifact: Path, server: str, *extra: str) -> object:
    return RUNNER.invoke(
        app,
        [
            "scan",
            str(artifact),
            "--api",
            server,
            "--attested-by",
            "kyle",
            "--attestation-ref",
            "SEC-1",
            "--poll-interval",
            "0.01",
            *extra,
        ],
    )


# --- exit codes: the contract with the pipeline ---------------------------


def test_pass_exits_zero(artifact: Path, server: str) -> None:
    result = _invoke(artifact, server)
    assert result.exit_code == 0
    assert "PASS" in result.stdout


def test_blocked_exits_one(artifact: Path, server: str) -> None:
    STATE["gate_response"] = _gate_payload(
        "blocked",
        1,
        violations=[
            {
                "kind": "severity_floor",
                "detail": "critical finding blocks release",
                "finding_id": "abc123",
                "rule_id": "aws_secret_key",
                "severity": "critical",
                "title": "AWS secret access key",
                "artifact_path": "installer.exe",
            }
        ],
        counts_by_severity={"critical": 1},
        new_counts_by_severity={"critical": 1},
        total_findings=1,
    )
    result = _invoke(artifact, server)
    assert result.exit_code == 1
    assert "BLOCKED" in result.stdout
    assert "AWS secret access key" in result.stdout


def test_inconclusive_exits_three(artifact: Path, server: str) -> None:
    STATE["gate_response"] = _gate_payload(
        "inconclusive",
        3,
        degraded_stages=["unpack (oom)"],
        violations=[{"kind": "degraded_scan", "detail": "scan incomplete"}],
    )
    result = _invoke(artifact, server)
    assert result.exit_code == 3
    assert "INCONCLUSIVE" in result.stdout


def test_unreachable_api_exits_two_not_one(artifact: Path) -> None:
    """A scanner outage must not look like a policy failure."""
    result = RUNNER.invoke(
        app,
        [
            "scan",
            str(artifact),
            "--api",
            "http://127.0.0.1:9",
            "--attested-by",
            "kyle",
            "--attestation-ref",
            "SEC-1",
        ],
    )
    assert result.exit_code == 2


def test_missing_attestation_exits_two(artifact: Path, server: str, monkeypatch) -> None:
    """No attestation, no ingestion — and it fails before uploading anything."""
    for var in (
        "GITHUB_ACTOR",
        "GITLAB_USER_LOGIN",
        "BUILD_REQUESTEDFOR",
        "CHANGE_AUTHOR",
        "GITHUB_SERVER_URL",
        "CI_PIPELINE_URL",
        "BUILD_BUILDURI",
        "BUILD_URL",
        "BARE_ATTESTED_BY",
        "BARE_ATTESTATION_REF",
    ):
        monkeypatch.delenv(var, raising=False)

    result = RUNNER.invoke(app, ["scan", str(artifact), "--api", server])
    assert result.exit_code == 2
    assert "attestation is required" in result.output
    assert "upload_body" not in STATE


def test_missing_artifact_exits_two(server: str) -> None:
    result = RUNNER.invoke(
        app,
        [
            "scan",
            "no-such-file.exe",
            "--api",
            server,
            "--attested-by",
            "k",
            "--attestation-ref",
            "r",
        ],
    )
    assert result.exit_code == 2


def test_warn_only_reports_but_exits_zero(artifact: Path, server: str) -> None:
    STATE["gate_response"] = _gate_payload("blocked", 1)
    result = _invoke(artifact, server, "--warn-only")
    assert result.exit_code == 0
    assert "BLOCKED" in result.stdout


# --- the upload itself -----------------------------------------------------


def test_upload_is_well_formed_multipart(artifact: Path, server: str) -> None:
    _invoke(artifact, server)
    body = STATE["upload_body"]
    assert isinstance(body, bytes)
    assert b'name="file"; filename="installer.exe"' in body
    assert b"MZ\x90\x00" in body
    assert b'name="attested_by"' in body
    assert b"kyle" in body
    assert "multipart/form-data; boundary=" in str(STATE["upload_content_type"])


def test_policy_and_waivers_travel_to_the_server(
    artifact: Path, server: str, tmp_path: Path
) -> None:
    """The policy goes to the API; the findings do not come back."""
    policy_dir = tmp_path / ".bare"
    policy_dir.mkdir()
    (policy_dir / "policy.yaml").write_text(
        "version: 1\nname: strict\nblock:\n  severity_at_or_above: critical\n", encoding="utf-8"
    )
    (policy_dir / "waivers.yaml").write_text(
        "waivers:\n  - finding_id: f1\n    reason: r\n    owner: o\n    expires: 2099-01-01\n",
        encoding="utf-8",
    )

    result = _invoke(artifact, server, "--policy", str(policy_dir / "policy.yaml"))
    assert result.exit_code == 0

    request = STATE["gate_request"]
    assert isinstance(request, dict)
    assert "name: strict" in request["policy_yaml"]
    assert "finding_id: f1" in request["waivers_yaml"]


def test_malformed_policy_fails_before_uploading(
    artifact: Path, server: str, tmp_path: Path
) -> None:
    """A typo should cost two seconds, not a full scan of a 2 GB installer."""
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\nblock:\n  severity_at_or_above: catastrophic\n", encoding="utf-8")

    result = _invoke(artifact, server, "--policy", str(bad))
    assert result.exit_code == 2
    assert "catastrophic" in result.output
    assert "upload_body" not in STATE


# --- output files ----------------------------------------------------------


def test_writes_json_sarif_and_markdown(artifact: Path, server: str, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _invoke(
        artifact,
        server,
        "--json",
        str(out / "verdict.json"),
        "--sarif",
        str(out / "scan.sarif"),
        "--markdown",
        str(out / "summary.md"),
    )
    assert result.exit_code == 0

    verdict = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["decision"] == "pass"
    assert verdict["run_id"] == "run-1"

    assert json.loads((out / "scan.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "BARE release gate" in (out / "summary.md").read_text(encoding="utf-8")


def test_waits_for_a_running_scan_before_gating(artifact: Path, server: str) -> None:
    """The run is queued at first and completes on a later poll."""
    polls = {"n": 0}
    STATE["run_status"] = "running"

    def complete_the_run() -> None:
        polls["n"] += 1
        STATE["run_status"] = "completed"

    timer = threading.Timer(0.05, complete_the_run)
    timer.start()
    try:
        result = _invoke(artifact, server)
    finally:
        timer.cancel()

    assert result.exit_code == 0
    assert polls["n"] == 1


# --- `bare gate`: re-evaluate without re-uploading -------------------


def _invoke_gate(server: str, *extra: str) -> object:
    return RUNNER.invoke(app, ["gate", "run-1", "--api", server, *extra])


def test_gate_reevaluates_without_uploading(artifact: Path, server: str) -> None:
    """The point of the command: no artifact, no upload, still a verdict."""
    result = _invoke_gate(server)
    assert result.exit_code == 0
    assert "PASS" in result.stdout
    assert "upload_body" not in STATE


def test_gate_blocked_exits_one(server: str) -> None:
    STATE["gate_response"] = _gate_payload(
        "blocked",
        1,
        violations=[
            {
                "kind": "severity_floor",
                "detail": "critical finding blocks release",
                "finding_id": "abc123",
                "rule_id": "aws_secret_key",
                "severity": "critical",
                "title": "AWS secret access key",
                "artifact_path": "installer.exe",
            }
        ],
    )
    result = _invoke_gate(server)
    assert result.exit_code == 1
    assert "BLOCKED" in result.stdout


def test_gate_sends_a_policy_and_a_baseline_override(server: str, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\nname: release\nbaseline:\n  mode: all\n", encoding="utf-8"
    )
    result = _invoke_gate(server, "--policy", str(policy), "--baseline-run", "run-0")
    assert result.exit_code == 0

    request = STATE["gate_request"]
    assert isinstance(request, dict)
    assert "name: release" in request["policy_yaml"]
    assert request["baseline_run_id"] == "run-0"


def test_gate_writes_its_outputs(server: str, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _invoke_gate(
        server, "--json", str(out / "verdict.json"), "--sarif", str(out / "scan.sarif")
    )
    assert result.exit_code == 0
    assert json.loads((out / "verdict.json").read_text(encoding="utf-8"))["run_id"] == "run-1"
    assert json.loads((out / "scan.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_gate_unreachable_api_exits_two(tmp_path: Path) -> None:
    result = RUNNER.invoke(app, ["gate", "run-1", "--api", "http://127.0.0.1:9"])
    assert result.exit_code == 2


def test_gate_malformed_policy_fails_before_calling(server: str, tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\non_degraded: shrug\n", encoding="utf-8")
    result = _invoke_gate(server, "--policy", str(bad))
    assert result.exit_code == 2
    assert "gate_request" not in STATE
