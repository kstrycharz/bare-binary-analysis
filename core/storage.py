"""Object storage for artifacts and extracted files.

S3-compatible via MinIO, which is what makes air-gapped deployment possible —
the same code path works against a MinIO container on an isolated host and
against S3 in a cloud deployment, with no branching.

Artifacts are addressed by content hash, so re-uploading the same build is free
and two runs over the same bytes provably analysed the same bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, BinaryIO

import structlog

from core.config import get_settings

log = structlog.get_logger(__name__)

_HASH_CHUNK = 1024 * 1024


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    sha256: str
    size_bytes: int


def hash_stream(stream: BinaryIO) -> tuple[str, int]:
    """SHA-256 and size, without loading the file into memory.

    Leaves the stream positioned at the start so the caller can upload it next.
    """
    digest = hashlib.sha256()
    size = 0
    stream.seek(0)
    while chunk := stream.read(_HASH_CHUNK):
        digest.update(chunk)
        size += len(chunk)
    stream.seek(0)
    return digest.hexdigest(), size


def hash_file(path: Path) -> tuple[str, int]:
    with path.open("rb") as handle:
        return hash_stream(handle)


def artifact_key(sha256: str, name: str) -> str:
    """Content-addressed. The name is kept only as a readable suffix; the hash
    is what identifies the object."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120]
    return f"artifacts/{sha256[:2]}/{sha256}/{safe}"


class ObjectStore:
    def __init__(self, client: Any | None = None, bucket: str | None = None) -> None:
        settings = get_settings()
        self._client = client
        self._bucket = bucket or settings.s3_bucket_artifacts

    @property
    def bucket(self) -> str:
        """The bucket this store writes to. Public because non-artifact
        objects (stage logs) share it under a distinct prefix and must not
        re-derive it from settings and drift."""
        return self._bucket

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3
            from botocore.config import Config

            settings = get_settings()
            self._client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint_url,
                aws_access_key_id=settings.s3_access_key,
                aws_secret_access_key=settings.s3_secret_key,
                region_name=settings.s3_region,
                config=Config(
                    signature_version="s3v4",
                    # Path-style addressing: virtual-host style requires DNS
                    # entries per bucket, which nobody has on an isolated host.
                    s3={"addressing_style": "path"},
                    retries={"max_attempts": 3},
                ),
            )
        return self._client

    def ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self._bucket)
        except Exception:
            log.info("storage.creating_bucket", bucket=self._bucket)
            self.client.create_bucket(Bucket=self._bucket)

    def put_stream(self, stream: BinaryIO, *, name: str) -> StoredObject:
        sha256, size = hash_stream(stream)
        key = artifact_key(sha256, name)
        self.ensure_bucket()
        self.client.upload_fileobj(stream, self._bucket, key)
        log.info("storage.stored", key=key, size_bytes=size)
        return StoredObject(key=key, sha256=sha256, size_bytes=size)

    def put_file(self, path: Path, *, name: str | None = None) -> StoredObject:
        with path.open("rb") as handle:
            return self.put_stream(handle, name=name or path.name)

    def download_to(self, key: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as handle:
            self.client.download_fileobj(self._bucket, key, handle)
        return destination

    def read_range(self, key: str, offset: int, length: int) -> bytes:
        """Byte range, for the hex viewer.

        A ranged GET rather than a full download: the finding detail page must
        not pull a 40 MB installer to show 256 bytes around an offset.
        """
        end = offset + max(length, 1) - 1
        response = self.client.get_object(
            Bucket=self._bucket, Key=key, Range=f"bytes={offset}-{end}"
        )
        body: bytes = response["Body"].read()
        return body

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self._bucket, Key=key)
        except Exception:
            return False
        return True


@lru_cache(maxsize=1)
def get_object_store() -> ObjectStore:
    return ObjectStore()
