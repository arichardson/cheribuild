import datetime
import shlex
import sys
import typing
from pathlib import Path

# boot_automation requires the vendored pexpect/ptyprocess on sys.path before it can be
# imported; normally done by cheribuild.py/test-scripts/run_tests_common.py.
_cheribuild_root = Path(__file__).parent.parent
_pexpect_dir = _cheribuild_root / "3rdparty/pexpect"
assert (_pexpect_dir / "pexpect/__init__.py").exists()
_ptyprocess_dir = _cheribuild_root / "3rdparty/ptyprocess"
assert (_ptyprocess_dir / "ptyprocess/ptyprocess.py").exists()
sys.path.insert(1, str(_pexpect_dir))
sys.path.insert(1, str(_ptyprocess_dir))

import pytest  # noqa: E402

from pycheribuild.boot_automation import _common, freebsd, linux  # noqa: E402
from pycheribuild.config.compilation_targets import CompilationTargets, linux_test_architecture_key  # noqa: E402

_TEST_XTARGET = CompilationTargets.CHERI_LINUX_RISCV64_PURECAP_093


class _RecordingGuest(_common.GuestInstance):
    """A real (non-QEMU) pexpect subprocess wired up with a guest OS's real PANIC_REGEXES,
    so tests exercise the actual matching/panic-detection code against real process output
    instead of a hand-rolled fake expect() implementation."""

    EXIT_ON_KERNEL_PANIC = False

    def __init__(self, *args, panic_regexes, real_handle_kernel_panic, **kwargs):
        super().__init__(*args, **kwargs)
        self.PANIC_REGEXES = panic_regexes
        self._real_handle_kernel_panic = real_handle_kernel_panic
        self.panic_detected = False

    def handle_kernel_panic(self):
        self.panic_detected = True
        self._real_handle_kernel_panic(self)


def _spawn_transcript(text: str, *, panic_regexes, real_handle_kernel_panic) -> _RecordingGuest:
    # Spawn a real process that emits canned "boot log" text and then echoes back whatever
    # it's sent, so tests exercise pexpect's real pattern matching against a real
    # subprocess/pty rather than a mocked/hand-rolled expect() implementation.
    script = f"printf '%s' {shlex.quote(text)}; exec cat"
    return _RecordingGuest(
        _TEST_XTARGET,
        "/bin/sh",
        ["-c", script],
        timeout=10,
        encoding="utf-8",
        panic_regexes=panic_regexes,
        real_handle_kernel_panic=real_handle_kernel_panic,
    )


def test_boot_and_login_linux_recognizes_busybox_prompt():
    # This only exercises the initial prompt-recognition step (what boot_and_login_linux's
    # first child.expect() call does), not the PS1-normalization step that follows it: that
    # relies on a real shell's backslash-escape processing of the PS1 string, which "cat"
    # (used here to avoid depending on any particular host shell's PS1 escaping rules) does
    # not do.
    boot_log = (
        "[    0.000000] Booting Linux on physical CPU 0x0\n"
        "[    0.123456] Run /init as init process\n"
        "Starting network...\n"
        "udhcpc: started, v1.36.1\n"
        "# "
    )
    child = _spawn_transcript(
        boot_log,
        panic_regexes=linux.QemuLinuxInstance.PANIC_REGEXES,
        real_handle_kernel_panic=linux.QemuLinuxInstance.handle_kernel_panic,
    )
    try:
        index = child.expect(
            [_common.INITIAL_PROMPT_SH], timeout=10, timeout_msg="timeout waiting for busybox shell prompt"
        )
        assert index == 0
        assert not child.panic_detected
    finally:
        child.close(force=True)


def test_expect_detects_linux_kernel_panic_in_realistic_boot_output():
    boot_log = (
        "[    0.000000] Booting Linux on physical CPU 0x0\n"
        f"[    1.234567] {linux.LINUX_PANIC}: VFS: Unable to mount root fs\n"
    )
    child = _spawn_transcript(
        boot_log,
        panic_regexes=linux.QemuLinuxInstance.PANIC_REGEXES,
        real_handle_kernel_panic=linux.QemuLinuxInstance.handle_kernel_panic,
    )
    try:
        child.expect(["# "], timeout=10, timeout_msg="did not see prompt or panic")
        assert child.panic_detected, "kernel panic in boot output was not detected"
    finally:
        child.close(force=True)


def test_expect_detects_freebsd_kernel_panic_in_realistic_boot_output():
    # PANIC ("panic: trap") is the *first* entry in FreeBSDSpawnMixin.PANIC_REGEXES -- the
    # specific entry an earlier off-by-one bug in _expect_and_handle_panic_impl caused to be
    # silently ignored (only the second and later panic regexes were ever detected).
    boot_log = "Trying to mount root from ufs:/dev/da0s1a\npanic: trap\n"
    child = _spawn_transcript(
        boot_log,
        panic_regexes=freebsd.FreeBSDSpawnMixin.PANIC_REGEXES,
        real_handle_kernel_panic=lambda self: None,  # avoid pulling in debug_kernel_panic()'s db> interaction
    )
    try:
        child.expect(["login:"], timeout=10, timeout_msg="did not see prompt or panic")
        assert child.panic_detected, "kernel panic in boot output was not detected"
    finally:
        child.close(force=True)


@pytest.mark.parametrize(
    ("name", "regexes"),
    [
        ("freebsd", freebsd.FreeBSDSpawnMixin.PANIC_REGEXES),
        ("linux", linux.QemuLinuxInstance.PANIC_REGEXES),
    ],
)
def test_panic_regexes_are_plain_strings(name, regexes):
    # PANIC_REGEXES entries get appended to whatever pattern list is passed to either
    # expect() (regex-capable) or expect_exact() (which rejects compiled re.Pattern objects
    # with a TypeError at runtime), so every entry must be a plain string to be safe for both.
    assert regexes, f"{name} PANIC_REGEXES should not be empty"
    for pattern in regexes:
        assert isinstance(pattern, str), f"{name} PANIC_REGEXES entry {pattern!r} is not a plain string"


def test_freebsd_overrides_ld_library_path_setup():
    assert (
        freebsd.QemuFreeBSDInstance.set_ld_library_path_with_sysroot
        is freebsd.FreeBSDSpawnMixin.set_ld_library_path_with_sysroot
    )
    assert (
        freebsd.FreeBSDSpawnMixin.set_ld_library_path_with_sysroot
        is not _common.GuestSpawnMixin.set_ld_library_path_with_sysroot
    )


def test_linux_uses_default_ld_library_path_setup():
    assert (
        linux.QemuLinuxInstance.set_ld_library_path_with_sysroot
        is _common.GuestSpawnMixin.set_ld_library_path_with_sysroot
    )


def test_freebsd_overrides_kernel_panic_handler():
    assert freebsd.FreeBSDSpawnMixin.handle_kernel_panic is not _common.GuestSpawnMixin.handle_kernel_panic


def test_linux_overrides_kernel_panic_handler():
    assert linux.QemuLinuxInstance.handle_kernel_panic is not _common.GuestSpawnMixin.handle_kernel_panic


def test_parse_smb_mount_basic():
    mount = _common.parse_smb_mount("/host/path:/target/path")
    assert mount.hostdir == Path("/host/path")
    assert mount.in_target == "/target/path"
    assert mount.readonly is False
    assert mount.qemu_arg == "/host/path"


def test_parse_smb_mount_readonly():
    mount = _common.parse_smb_mount("/host/path@ro:/target/path")
    assert mount.hostdir == Path("/host/path")
    assert mount.readonly is True
    assert mount.qemu_arg == "/host/path@ro"


def test_mount_via_9p_linux_builds_correct_command(monkeypatch):
    calls = []
    monkeypatch.setattr(linux, "checked_run_guest_command", lambda qemu, cmd, **kw: calls.append(cmd))
    mount = _common.SharedMount(Path("/host"), readonly=False, in_target="/target")

    result = linux.mount_via_9p_linux(mount, qemu=typing.cast(linux.QemuGuestInstance, None), share_name="qemu1")

    assert result is True
    assert mount.mounted is True
    assert calls == ["mount -t 9p -o trans=virtio,version=9p2000.L qemu1 '/target'"]


def test_mount_via_9p_linux_readonly_adds_ro_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(linux, "checked_run_guest_command", lambda qemu, cmd, **kw: calls.append(cmd))
    mount = _common.SharedMount(Path("/host"), readonly=True, in_target="/target")

    linux.mount_via_9p_linux(mount, qemu=typing.cast(linux.QemuGuestInstance, None), share_name="qemu2")

    assert calls == ["mount -t 9p -o trans=virtio,version=9p2000.L,ro qemu2 '/target'"]


def test_mount_via_9p_linux_failure_leaves_unmounted(monkeypatch):
    def fake_checked_run(qemu, cmd, **kwargs):
        raise _common.CommandFailedError("boom", execution_time=datetime.timedelta(seconds=1))

    monkeypatch.setattr(linux, "checked_run_guest_command", fake_checked_run)
    mount = _common.SharedMount(Path("/host"), readonly=False, in_target="/target")

    result = linux.mount_via_9p_linux(mount, qemu=typing.cast(linux.QemuGuestInstance, None), share_name="qemu3")

    assert result is False
    assert mount.mounted is False


def test_linux_test_architecture_keys_are_unique():
    all_linux_targets = (
        *CompilationTargets.ALL_UPSTREAM_LINUX_TARGETS,
        *CompilationTargets.ALL_CHERI_LINUX_TARGETS,
        *CompilationTargets.ALL_MORELLO_LINUX_TARGETS,
    )
    keys = [linux_test_architecture_key(x) for x in all_linux_targets]
    assert len(keys) == len(set(keys)), f"Duplicate linux_test_architecture_key() values: {keys}"


def test_linux_test_architecture_keys_dont_collide_with_freebsd():
    all_linux_targets = (
        *CompilationTargets.ALL_UPSTREAM_LINUX_TARGETS,
        *CompilationTargets.ALL_CHERI_LINUX_TARGETS,
        *CompilationTargets.ALL_MORELLO_LINUX_TARGETS,
    )
    linux_keys = {linux_test_architecture_key(x) for x in all_linux_targets}
    assert linux_keys.isdisjoint(freebsd.SUPPORTED_ARCHITECTURES.keys())
