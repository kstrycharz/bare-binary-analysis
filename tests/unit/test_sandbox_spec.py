"""The spec is the chokepoint for isolation, so its guards get tested hard.

These tests are cheap and run without Docker. They are the first thing that
catches "someone added an analyzer that quietly needs CAP_SYS_ADMIN".
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from core.sandbox.images import analyzer_image
from core.sandbox.spec import (
    INPUT_DIR,
    OUTPUT_DIR,
    BindMount,
    MountMode,
    NetworkMode,
    SandboxSpec,
    SpecViolation,
    TmpfsMount,
)


def make_spec(**overrides: object) -> SandboxSpec:
    base = {
        "image": analyzer_image("hello"),
        "run_id": "run-1",
        "analyzer": "hello",
    }
    return SandboxSpec(**{**base, **overrides})  # type: ignore[arg-type]


class TestDefaults:
    def test_defaults_are_locked_down(self) -> None:
        spec = make_spec()
        assert spec.network is NetworkMode.NONE
        assert spec.read_only_rootfs is True
        assert spec.user == "10001:10001"
        assert spec.cap_drop == ("ALL",)
        assert spec.cap_add == ()
        assert spec.no_new_privileges is True
        assert spec.seccomp_profile is not None
        spec.validate()

    def test_labels_let_the_reaper_find_it(self) -> None:
        labels = make_spec().labels
        assert labels["bare.run"] == "run-1"
        assert labels["bare.analyzer"] == "hello"
        assert labels["bare.managed"] == "true"

    def test_spec_is_hashable_so_it_can_go_in_a_manifest(self) -> None:
        assert hash(make_spec()) == hash(make_spec())


class TestValidation:
    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"user": "0:0"}, "root"),
            ({"cap_drop": ()}, "cap_drop"),
            ({"cap_add": ("SYS_ADMIN",)}, "cap_add"),
            ({"no_new_privileges": False}, "no_new_privileges"),
            ({"read_only_rootfs": False}, "read-only"),
            ({"timeout_s": 0}, "timeout_s"),
            ({"pids_limit": 0}, "pids_limit"),
            ({"mem_limit_bytes": 0}, "mem_limit_bytes"),
            ({"run_id": ""}, "run_id"),
        ],
    )
    def test_rejects_weakened_isolation(self, overrides: dict[str, object], expected: str) -> None:
        with pytest.raises(SpecViolation) as exc:
            make_spec(**overrides).validate()
        assert expected in str(exc.value)

    def test_refuses_the_docker_socket(self) -> None:
        spec = make_spec(
            mounts=(BindMount("/var/run/docker.sock", PurePosixPath("/var/run/docker.sock")),)
        )
        with pytest.raises(SpecViolation, match="Docker socket"):
            spec.validate()

    def test_input_must_be_read_only(self) -> None:
        spec = make_spec(mounts=(BindMount("/runs/r1/staging", INPUT_DIR, MountMode.READ_WRITE),))
        with pytest.raises(SpecViolation, match="/input"):
            spec.validate()

    def test_output_must_be_writable(self) -> None:
        spec = make_spec(mounts=(BindMount("/runs/r1/out", OUTPUT_DIR, MountMode.READ_ONLY),))
        with pytest.raises(SpecViolation, match="/output"):
            spec.validate()

    def test_at_most_one_writable_mount(self) -> None:
        spec = make_spec(
            mounts=(
                BindMount("/runs/r1/out", OUTPUT_DIR, MountMode.READ_WRITE),
                BindMount("/runs/r1/other", PurePosixPath("/other"), MountMode.READ_WRITE),
            )
        )
        with pytest.raises(SpecViolation, match="writable mount"):
            spec.validate()

    def test_canonical_mount_pair_is_accepted(self) -> None:
        make_spec(
            mounts=(
                BindMount("/runs/r1/staging", INPUT_DIR, MountMode.READ_ONLY),
                BindMount("/runs/r1/results", OUTPUT_DIR, MountMode.READ_WRITE),
            )
        ).validate()


class TestOverrides:
    def test_resource_overrides_are_allowed(self) -> None:
        spec = make_spec().with_overrides(mem_limit_bytes=16 * 1024**3, timeout_s=1800)
        assert spec.mem_limit_bytes == 16 * 1024**3
        assert spec.timeout_s == 1800
        spec.validate()

    @pytest.mark.parametrize(
        "field",
        ["network", "read_only_rootfs", "user", "cap_drop", "no_new_privileges"],
    )
    def test_isolation_fields_cannot_be_overridden(self, field: str) -> None:
        with pytest.raises(ValueError, match="refusing to weaken isolation"):
            make_spec().with_overrides(**{field: None})


class TestTmpfs:
    def test_default_tmpfs_denies_exec_in_tmp(self) -> None:
        tmp = next(t for t in make_spec().tmpfs if str(t.target) == "/tmp")
        assert "noexec" in tmp.to_options()

    def test_work_allows_exec_for_unpackers(self) -> None:
        work = next(t for t in make_spec().tmpfs if str(t.target) == "/work")
        options = work.to_options()
        assert "noexec" not in options
        assert "nosuid" in options and "nodev" in options

    def test_option_rendering(self) -> None:
        mount = TmpfsMount(PurePosixPath("/tmp"), size_bytes=1024)
        assert mount.to_options() == "size=1024,mode=770,uid=10001,gid=10001,noexec,nosuid,nodev"

    @pytest.mark.parametrize("target", ["/tmp", "/work"])
    def test_scratch_space_is_owned_by_the_analyzer_user(self, target: str) -> None:
        """A tmpfs masks the image's chown and defaults to root:root 0755, so
        without explicit ownership the analyzer cannot write to its own scratch
        directory — which presents as a broken analyzer, not a broken mount."""
        mount = next(t for t in make_spec().tmpfs if str(t.target) == target)
        options = mount.to_options()
        assert "uid=10001" in options
        assert "gid=10001" in options
