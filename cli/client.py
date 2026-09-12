"""A minimal BARE API client for CI runners.

Standard library only, on purpose. This is the one component that gets
installed on every build agent in a company, and "add a scanner to the
pipeline" should not mean "resolve a dependency tree on a locked-down build
image". ``urllib`` is unglamorous and present everywhere, which is exactly the
trade this file is making.

The upload streams. A 2 GB installer must never have to fit in the build
agent's memory, which rules out reading the file to build a multipart body —
so the body is assembled as a lazily-read stream with a known content length.
"""

from __future__ import annotations

import json
import mimetypes
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

USER_AGENT = "bare-cli"
DEFAULT_TIMEOUT_S = 60.0


class ApiError(RuntimeError):
    """The API rejected a request or could not be reached.

    Distinct from a policy failure throughout: a build that could not be
    scanned and a build that failed its gate need different responses, and
    collapsing them teaches people to treat both as flaky.
    """

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class _MultipartBody:
    """A streaming multipart/form-data body.

    Exposes ``read`` so ``urllib`` treats it as a file object, and a known
    ``content_length`` so the request does not need chunked encoding — some
    corporate proxies still mishandle it.
    """

    def __init__(self, fields: dict[str, str], file_field: str, path: Path) -> None:
        self.boundary = uuid.uuid4().hex
        self._path = path
        self._preamble = self._build_preamble(fields, file_field, path)
        self._epilogue = f"\r\n--{self.boundary}--\r\n".encode()
        self._file_size = path.stat().st_size
        self._handle: BinaryIO | None = None
        self._stage: Iterator[bytes] | None = None
        self._buffer = b""
        self._done_preamble = False
        self._done_file = False

    def _build_preamble(self, fields: dict[str, str], file_field: str, path: Path) -> bytes:
        parts: list[str] = []
        for name, value in sorted(fields.items()):
            parts.append(f"--{self.boundary}\r\n")
            parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n')
            parts.append(f"{value}\r\n")
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        parts.append(f"--{self.boundary}\r\n")
        parts.append(
            f'Content-Disposition: form-data; name="{file_field}"; filename="{path.name}"\r\n'
        )
        parts.append(f"Content-Type: {content_type}\r\n\r\n")
        return "".join(parts).encode("utf-8")

    @property
    def content_type(self) -> str:
        return f"multipart/form-data; boundary={self.boundary}"

    @property
    def content_length(self) -> int:
        return len(self._preamble) + self._file_size + len(self._epilogue)

    def read(self, size: int = -1) -> bytes:
        if not self._done_preamble:
            self._done_preamble = True
            self._handle = self._path.open("rb")
            return self._preamble
        if not self._done_file:
            assert self._handle is not None
            chunk = self._handle.read(size if size and size > 0 else 1024 * 1024)
            if chunk:
                return chunk
            self._done_file = True
            self._handle.close()
            self._handle = None
            return self._epilogue
        return b""

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


@dataclass(frozen=True, slots=True)
class RunHandle:
    run_id: str
    artifact_name: str
    artifact_sha256: str
    size_bytes: int
    status: str


class BareClient:
    """Talks to one BARE deployment."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout_s = timeout_s

    # -- plumbing ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: _MultipartBody | bytes | None = None,
        content_type: str = "",
        timeout_s: float | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = self._headers()
        data: Any = body

        if isinstance(body, _MultipartBody):
            headers["Content-Type"] = body.content_type
            headers["Content-Length"] = str(body.content_length)
        elif content_type:
            headers["Content-Type"] = content_type

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            # The base URL is operator-supplied configuration, not attacker input.
            with urllib.request.urlopen(request, timeout=timeout_s or self._timeout_s) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise ApiError(
                f"{method} {path} failed: HTTP {exc.code}", status=exc.code, body=detail
            ) from None
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {self.base_url}: {exc.reason}") from None
        except TimeoutError:
            # A read that stalls *after* the response headers arrive raises a
            # bare TimeoutError, not URLError — so it escaped both handlers
            # above and reached a build agent as a Python traceback. A CI step
            # gets a sentence and an exit code, never a stack.
            raise ApiError(
                f"{method} {path} timed out after {timeout_s or self._timeout_s:.0f}s. "
                f"Large artifacts can exceed the default; raise --timeout."
            ) from None
        except OSError as exc:
            raise ApiError(f"{method} {path} failed: {exc}") from None
        finally:
            if isinstance(body, _MultipartBody):
                body.close()

        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(f"{method} {path} returned non-JSON: {raw[:200]}") from None

    # -- operations -------------------------------------------------------

    def health(self) -> dict[str, Any]:
        result = self._request("GET", "/readyz", timeout_s=10)
        return dict(result or {})

    def upload(
        self,
        path: Path,
        *,
        attested_by: str,
        attestation_reference: str,
        profile: str = "standard",
        llm_enabled: bool = False,
    ) -> RunHandle:
        """Submit an artifact and queue a scan."""
        if not path.is_file():
            raise ApiError(f"{path} is not a file")

        body = _MultipartBody(
            {
                "profile": profile,
                "attested_by": attested_by,
                "attestation_reference": attestation_reference,
                "llm_enabled": "true" if llm_enabled else "false",
                "retain_plaintext": "false",
            },
            "file",
            path,
        )
        # Uploads are slow for large installers; the read timeout has to cover
        # the transfer, not just the handshake.
        payload = self._request("POST", "/api/runs", body=body, timeout_s=max(self._timeout_s, 900))
        if not isinstance(payload, dict):
            raise ApiError("upload returned an unexpected payload")
        return RunHandle(
            run_id=str(payload["run_id"]),
            artifact_name=str(payload.get("artifact_name", path.name)),
            artifact_sha256=str(payload.get("artifact_sha256", "")),
            size_bytes=int(payload.get("size_bytes", 0)),
            status=str(payload.get("status", "queued")),
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        result = self._request("GET", f"/api/runs/{run_id}")
        return dict(result or {})

    def get_gate(
        self,
        run_id: str,
        *,
        policy_yaml: str = "",
        waivers_yaml: str = "",
        baseline_run_id: str = "",
    ) -> dict[str, Any]:
        """Ask the server to evaluate the gate.

        The policy travels *to* the server rather than the findings travelling
        back: the findings list is the company's exposed secrets, and a CI log
        is not where it should be reassembled.
        """
        payload = json.dumps(
            {
                "policy_yaml": policy_yaml,
                "waivers_yaml": waivers_yaml,
                "baseline_run_id": baseline_run_id or None,
            }
        ).encode("utf-8")
        result = self._request(
            "POST",
            f"/api/runs/{run_id}/gate",
            body=payload,
            content_type="application/json",
        )
        return dict(result or {})

    def get_pdf(self, run_id: str) -> bytes:
        """The release record. Returns raw bytes rather than JSON."""
        url = f"{self.base_url}/api/runs/{run_id}/report.pdf"
        request = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as exc:
            raise ApiError(f"GET report.pdf failed: HTTP {exc.code}", status=exc.code) from None
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {self.base_url}: {exc.reason}") from None
        except TimeoutError:
            raise ApiError(
                f"GET report.pdf timed out after {self._timeout_s:.0f}s. "
                f"Rendering a report for a large artifact can exceed the default; "
                f"raise --timeout."
            ) from None
        except OSError as exc:
            raise ApiError(f"GET report.pdf failed: {exc}") from None

    def get_sbom(self, run_id: str) -> dict[str, Any]:
        result = self._request("GET", f"/api/runs/{run_id}/sbom")
        return dict(result or {})

    def get_sarif(self, run_id: str) -> dict[str, Any]:
        result = self._request("GET", f"/api/runs/{run_id}/sarif")
        return dict(result or {})

    def wait_for_run(
        self,
        run_id: str,
        *,
        timeout_s: float,
        poll_interval_s: float = 5.0,
        on_poll: Any = None,
    ) -> dict[str, Any]:
        """Poll until the run reaches a terminal state.

        Polling rather than streaming the SSE endpoint: a build agent behind a
        proxy that buffers responses would hang on an event stream, and the
        failure would look like a stuck pipeline rather than a network problem.
        """
        deadline = time.monotonic() + timeout_s
        terminal = {"completed", "degraded", "failed", "cancelled"}
        while True:
            run = self.get_run(run_id)
            status = str(run.get("status", ""))
            if status in terminal:
                return run
            if time.monotonic() >= deadline:
                raise ApiError(
                    f"run {run_id} did not finish within {timeout_s:.0f}s (last status: {status})"
                )
            if on_poll is not None:
                on_poll(run)
            time.sleep(poll_interval_s)
