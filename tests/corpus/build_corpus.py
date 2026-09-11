#!/usr/bin/env python3
"""Build the synthetic corpus.

A build target, not a download (§15). These artifacts contain deliberately
planted, **provably invalid** credentials so the scanner can be measured
against a known answer key.

Rules for anything added here:

* Never a real credential. Use shapes that are syntactically valid but
  cryptographically meaningless — the same discipline the false-positive
  corpus documents.
* Never a value that appears in ``detections/false_positives.yaml``. That
  corpus exists to drop documentation examples, so planting one here would
  assert the scanner is broken.
* Every planted secret is recorded in ``expected.json``, which is what the
  precision/recall harness grades against.

M1 generates PE-shaped files directly rather than compiling, so the corpus
builds identically on any platform without a toolchain. Real compiled
artifacts — a Go binary with build-path leakage, an NSIS installer, a squashfs
image — arrive with M2, when there is unpacking to exercise them.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "build"


@dataclass(frozen=True)
class Planted:
    """One deliberately embedded secret, and where we put it."""

    rule_id: str
    value: str
    encoding: str
    note: str


def _pe_header() -> bytes:
    """A minimal but structurally valid PE header.

    Enough that file identification reports 'pe' and 'x86_64' rather than
    'unknown' — the corpus should exercise the identify path, not bypass it.
    """
    dos = bytearray(b"MZ" + b"\x90\x00" * 29)
    dos += struct.pack("<I", 0x80)  # e_lfanew at 0x3C
    dos = dos.ljust(0x80, b"\x00")

    coff = b"PE\x00\x00"
    coff += struct.pack("<H", 0x8664)  # machine: x86_64
    coff += struct.pack("<H", 3)  # number of sections
    coff += struct.pack("<I", 0x67890000)  # timestamp
    coff += struct.pack("<I", 0)  # symbol table pointer
    coff += struct.pack("<I", 0)  # symbol count
    coff += struct.pack("<H", 0xF0)  # optional header size
    coff += struct.pack("<H", 0x0022)  # characteristics: executable, large address
    return bytes(dos) + coff


def _wide(text: str) -> bytes:
    """UTF-16LE, as a Windows binary stores its string resources."""
    return text.encode("utf-16le")


def build_vulnerable_installer(out: Path) -> list[Planted]:
    """A plausible Windows installer that leaked most of its build environment.

    Deliberately mirrors how this happens in reality: the AWS key sits in an
    ASCII config blob, while the provisioning token and PDB path live in
    UTF-16 resources — where scanners that only walk ASCII never look.
    """
    planted: list[Planted] = []
    blob = bytearray(_pe_header())
    blob += b"\x00" * 512

    # --- .rdata: ASCII config -------------------------------------------
    blob += b".rdata\x00\x00"
    ascii_section = "\n".join(
        [
            "SOFTWARE\\Example Corp\\Updater",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ExampleUpdater/4.2.1",
            "https://updates.example.com/v4/manifest.json",
            "aws_access_key_id = AKIA2E0A8F3B5C7D9E1F",
            "aws_secret_access_key = Kq2vN8xR4mT7wZ1cB5nH9jL3fD6gY0pA2sE4uI8o",
            "# NOTE: rotate before GA -- filed as RELEASE-4821",
            "telemetry_endpoint=https://telemetry-ingest.corp.example.com/v2/events",
            "jdbc:postgresql://db-prod-01.internal:5432/updater?user=svc_updater",
            "",
        ]
    )
    blob += ascii_section.encode("ascii")
    planted += [
        Planted("aws-access-key-id", "AKIA2E0A8F3B5C7D9E1F", "ascii", "config blob"),
        Planted(
            "aws-secret-access-key",
            "Kq2vN8xR4mT7wZ1cB5nH9jL3fD6gY0pA2sE4uI8o",
            "ascii",
            "config blob",
        ),
        Planted(
            "internal-hostname",
            "telemetry-ingest.corp.example.com",
            "ascii",
            "telemetry endpoint",
        ),
        Planted("internal-hostname", "db-prod-01.internal", "ascii", "jdbc host"),
    ]

    blob += b"\x00" * 256

    # --- .rsrc: UTF-16 resources ----------------------------------------
    # The headline case. A scanner that only extracts ASCII finds none of this.
    blob += b".rsrc\x00\x00\x00"
    blob += b"\x00" * 16
    for text in [
        "Example Corp Updater",
        "provisioning_token=ghp_9fK3mQ7xR2vN8pL4wY6tB1cH5jD0aZ3eS7uI",
        "MQTT_BROKER=mqtts://device-provisioning.internal:8883",
        "C:\\build\\agent\\_work\\42\\s\\Project Hummingbird\\Release\\updater.pdb",
        "FACTORY_MODE_ENABLE=0",
    ]:
        blob += _wide(text) + b"\x00\x00"
    planted += [
        Planted(
            "github-token",
            "ghp_9fK3mQ7xR2vN8pL4wY6tB1cH5jD0aZ3eS7uI",
            "utf-16le",
            "resource string — invisible to ASCII-only scanners",
        ),
        Planted(
            "internal-hostname",
            "device-provisioning.internal",
            "utf-16le",
            "MQTT broker",
        ),
        Planted(
            "pdb-source-path",
            "C:\\build\\agent\\_work\\42\\s\\Project Hummingbird\\Release\\updater.pdb",
            "utf-16le",
            "leaks build path, CI runner layout, and a project codename",
        ),
    ]

    blob += b"\x00" * 128

    # --- embedded PEM ----------------------------------------------------
    # Structurally a private key, cryptographically nothing. An automatic
    # critical, and the finding most likely to stop a release.
    blob += b".data\x00\x00\x00"
    blob += (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEAxNOTAREALKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        b"THISISSYNTHETICTESTDATAANDCONTAINSNOKEYMATERIALWHATSOEVERxxxxxxx\n"
        b"-----END RSA PRIVATE KEY-----\n"
    )
    planted.append(
        Planted(
            "private-key-pem",
            "-----BEGIN RSA PRIVATE KEY-----",
            "ascii",
            "embedded PEM — synthetic, no key material",
        )
    )

    # --- known false positives -------------------------------------------
    # Planted on purpose: a scanner that reports these is a scanner people mute.
    blob += b"\x00" * 64
    blob += (
        b"# Documentation examples that MUST NOT be reported:\n"
        b"# aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        b"# endpoint = https://www.example.com/api\n"
        b"# fallback = 127.0.0.1\n"
    )

    blob += b"\x00" * 1024
    out.write_bytes(bytes(blob))
    return planted


def build_clean_binary(out: Path) -> list[Planted]:
    """A control artifact with nothing to find.

    A scanner is only as trustworthy as its behaviour on clean input; this is
    what catches a rule that matches everything.
    """
    blob = bytearray(_pe_header())
    blob += b"\x00" * 512
    blob += b".rdata\x00\x00"
    blob += "\n".join(
        [
            "Example Corp Viewer",
            "https://www.example.com/help",
            "Copyright (c) 2026 Example Corp",
            "Unable to open the requested document.",
            "127.0.0.1",
            "AKIAIOSFODNN7EXAMPLE",
        ]
    ).encode("ascii")
    blob += b"\x00" * 512
    blob += _wide("Example Corp Viewer 2.1") + b"\x00\x00"
    out.write_bytes(bytes(blob))
    return []


def build_nested_release(out: Path, installer: Path) -> list[Planted]:
    """A release bundle three levels deep.

    The realistic shape: a zip a vendor publishes, containing the installer and
    a payload tarball, whose config file holds the staging token nobody
    remembered to strip. Findings must carry full provenance —
    ``release.zip → payload.tar.gz → config/prod.json`` — or the engineer
    cannot tell which build step to fix.
    """
    import io
    import tarfile
    import zipfile

    planted: list[Planted] = []

    # Level 3: the config file.
    config = json.dumps(
        {
            "environment": "staging",
            "api_base": "https://api-staging.corp.example.com",
            "service_token": "ghp_2xQ7mV4kR9wL6nB3tY8cH5jF1dA0zS7eU3iO",
            "telemetry": {"enabled": True, "key": "AIzaSyB7nK2mQ9xR4vT8wZ1cL5pN3jH6dF0gA2b"},
            "notes": "TODO: move token to runtime provisioning before GA",
        },
        indent=2,
    ).encode()
    planted += [
        Planted(
            "github-token",
            "ghp_2xQ7mV4kR9wL6nB3tY8cH5jF1dA0zS7eU3iO",
            "ascii",
            "release.zip -> payload.tar.gz -> config/prod.json",
        ),
        Planted(
            "google-api-key",
            "AIzaSyB7nK2mQ9xR4vT8wZ1cL5pN3jH6dF0gA2b",
            "ascii",
            "release.zip -> payload.tar.gz -> config/prod.json",
        ),
        Planted(
            "internal-hostname",
            "api-staging.corp.example.com",
            "ascii",
            "release.zip -> payload.tar.gz -> config/prod.json",
        ),
    ]

    # Level 2: a tarball holding that config.
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("config/prod.json")
        info.size = len(config)
        tar.addfile(info, io.BytesIO(config))

        readme = b"Internal build payload. Do not redistribute.\n"
        readme_info = tarfile.TarInfo("README.txt")
        readme_info.size = len(readme)
        tar.addfile(readme_info, io.BytesIO(readme))

    # Level 1: the published zip.
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.tar.gz", tar_buffer.getvalue())
        archive.write(installer, "bin/updater.exe")
        archive.writestr("VERSION", "4.2.1\n")

    # The installer's own planted secrets are reachable through this bundle too,
    # which is what proves findings dedupe across the tree rather than
    # multiplying.
    return planted


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the BARE synthetic corpus")
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    expected: dict[str, list[dict[str, str]]] = {}
    builders = {
        "vulnerable-installer.exe": build_vulnerable_installer,
        "clean-viewer.exe": build_clean_binary,
    }

    for name, builder in builders.items():
        path = args.out / name
        planted = builder(path)
        expected[name] = [asdict(p) for p in planted]
        print(f"  {name:28} {path.stat().st_size:>8} bytes  {len(planted)} planted")

    # Built last: it wraps the installer produced above.
    nested = args.out / "nested-release.zip"
    nested_planted = build_nested_release(nested, args.out / "vulnerable-installer.exe")
    expected["nested-release.zip"] = [asdict(p) for p in nested_planted]
    print(
        f"  {'nested-release.zip':28} {nested.stat().st_size:>8} bytes  "
        f"{len(nested_planted)} planted (3 levels deep)"
    )

    answer_key = args.out / "expected.json"
    answer_key.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nanswer key: {answer_key}")
    print("NOTE: every planted value is synthetic and cryptographically invalid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
