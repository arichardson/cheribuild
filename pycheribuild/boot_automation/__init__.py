#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
# -
# Copyright (c) 2016-2017 SRI International
# Copyright (c) 2017 Alex Richardson
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# runtests.py - run guest OS tests and export them to a tarfile via a disk
# device.
#
# Top-level dispatch/orchestration for the pexpect-driven boot/test
# automation. Guest-OS-agnostic pieces live in _common.py, FreeBSD/CheriBSD
# specifics in freebsd.py.
import argparse
import datetime
import os
import shutil
import socket
import sys
import tempfile
import time
import traceback
import typing
from collections.abc import Sequence
from pathlib import Path
from typing import Callable, Optional

_cheribuild_root = Path(__file__).parent.parent.parent
_pexpect_dir = _cheribuild_root / "3rdparty/pexpect"
assert (_pexpect_dir / "pexpect/__init__.py").exists()
assert str(_pexpect_dir.resolve()) in sys.path, str(_pexpect_dir) + " not found in " + str(sys.path)
import pexpect  # noqa: E402

from . import _common, freebsd, linux  # noqa: E402
from ._common import (  # noqa: E402
    CommandFailedError,
    CommandTimeoutError,
    FakeQemuSpawn,
    GuestInstance,
    GuestSpawnMixin,
    MatchedErrorOutputError,
    PatternListType,
    PretendSpawn,
    QemuGuestInstance,
    SharedMount,
    checked_run_guest_command,
    failure,
    info,
    maybe_decompress,
    parse_smb_mount,
    run_guest_command,
    run_host_command,
    success,
    warn,
)
from .freebsd import (  # noqa: E402
    QemuFreeBSDInstance,
    debug_kernel_panic,
    prepend_ld_library_path,
    setup_ssh_for_root_login,
)
from .linux import QemuLinuxInstance  # noqa: E402
from ..config.compilation_targets import CompilationTargets, linux_test_architecture_key  # noqa: E402
from ..config.target_info import CrossCompileTarget  # noqa: E402
from ..processutils import keep_terminal_sane, run_and_kill_children_on_exit  # noqa: E402
from ..qemu_utils import QemuOptions, qemu_supports_9pfs  # noqa: E402
from ..utils import ConfigBase, find_free_port, get_global_config, init_global_config  # noqa: E402

# Names re-exported for external callers (test-scripts/*.py access these as boot_automation.X).
__all__ = [
    "CommandFailedError",
    "CommandTimeoutError",
    "CrossCompileTarget",
    "FakeQemuSpawn",
    "GuestInstance",
    "GuestSpawnMixin",
    "MatchedErrorOutputError",
    "PatternListType",
    "PretendSpawn",
    "QemuFreeBSDInstance",
    "QemuGuestInstance",
    "QemuLinuxInstance",
    "SharedMount",
    "debug_kernel_panic",
    "failure",
    "get_argument_parser",
    "info",
    "main",
    "maybe_decompress",
    "prepend_ld_library_path",
    "run_host_command",
    "success",
    "warn",
]

SUPPORTED_ARCHITECTURES = dict(freebsd.SUPPORTED_ARCHITECTURES)
SUPPORTED_ARCHITECTURES.update(
    {
        linux_test_architecture_key(x): x
        for x in (
            *CompilationTargets.ALL_UPSTREAM_LINUX_TARGETS,
            *CompilationTargets.ALL_CHERI_LINUX_TARGETS,
            *CompilationTargets.ALL_MORELLO_LINUX_TARGETS,
        )
    }
)

# Set directly by external callers (e.g. run_libcxx_tests.py sets this per-shard); read fresh on
# every info()/warn()/success()/failure() call via _common._message_prefix(), not copied elsewhere.
MESSAGE_PREFIX: str = ""
QEMU_LOGFILE: "Optional[Path]" = None
# To keep the port available until we start QEMU
_SSH_SOCKET_PLACEHOLDER: "Optional[socket.socket]" = None


def default_ssh_key():
    for i in ("id_ed25519.pub", "id_rsa.pub"):
        guess = Path(os.path.expanduser("~/.ssh/"), i)
        if guess.exists():
            return str(guess)
    return None


def boot_guest(
    qemu_options: QemuOptions,
    qemu_command: Optional[Path],
    kernel_image: Optional[Path],
    disk_image: Optional[Path],
    ssh_port: Optional[int],
    ssh_pubkey: Optional[Path],
    *,
    write_disk_image_changes: bool,
    expected_kernel_abi: str,
    smp_args: "list[str]",
    shared_dirs: "Optional[list[SharedMount]]" = None,
    kernel_init_only=False,
    trap_on_unrepresentable=False,
    skip_ssh_setup=False,
    bios_path: "Optional[Path]" = None,
    boot_alternate_kernel_dir: "Optional[Path]" = None,
    initramfs_image: "Optional[Path]" = None,
) -> QemuGuestInstance:
    is_linux = qemu_options.xtarget.target_info_cls.is_linux()
    user_network_args = ""
    extra_qemu_args = []
    if shared_dirs is None:
        shared_dirs = []
    if shared_dirs:
        for idx, d in enumerate(shared_dirs):
            if not Path(d.hostdir).exists():
                failure("Shared directory ", d.hostdir, " doesn't exist!", exit=True)
            if qemu_supports_9pfs(qemu_command, config=get_global_config()):
                virtfs_arg = (
                    f"local,id=virtfs{idx + 1},mount_tag=qemu{idx + 1},path={d.hostdir},security_model=mapped-xattr"
                )
                if d.readonly:
                    virtfs_arg += ",readonly=on"
                extra_qemu_args.extend(["-virtfs", virtfs_arg])
        user_network_args += ",smb=" + ":".join(d.qemu_arg for d in shared_dirs)
    if ssh_port is not None:
        user_network_args += ",hostfwd=tcp::" + str(ssh_port) + "-:22"

    if not qemu_options.can_boot_kernel_directly:
        if not disk_image:
            failure("Cannot boot kernel directly and no disk image passed!", exit=True)
    if bios_path is not None:
        bios_args = ["-bios", str(bios_path)]
    else:
        bios_args = []
    qemu_args = qemu_options.get_commandline(
        qemu_command=qemu_command,
        kernel_file=kernel_image,
        disk_image=disk_image,
        bios_args=bios_args,
        user_network_args=user_network_args,
        write_disk_image_changes=write_disk_image_changes,
        add_network_device=True,
        trap_on_unrepresentable=trap_on_unrepresentable,  # For debugging
        add_virtio_rng=True,  # faster entropy gathering
    )
    qemu_args.extend(smp_args)
    qemu_args.extend(extra_qemu_args)
    if initramfs_image is not None:
        qemu_args.extend(["-initrd", str(initramfs_image)])
    kernel_commandline = []
    loader_kernel_dir: "Optional[Path]" = None
    if is_linux:
        kernel_commandline.append("init=/init")
    else:
        if qemu_options.can_boot_kernel_directly and kernel_image and boot_alternate_kernel_dir:
            kernel_commandline.append(f"kern.module_path={boot_alternate_kernel_dir}")
            loader_kernel_dir = None
        else:
            loader_kernel_dir = boot_alternate_kernel_dir
        if kernel_init_only:
            kernel_commandline.append("init_path=/sbin/startup-benchmark.sh")
        if skip_ssh_setup:
            kernel_commandline.append("cheribuild.skip_sshd=1")
            kernel_commandline.append("cheribuild.skip_entropy=1")
    if kernel_commandline:
        if kernel_image is not None and qemu_options.can_boot_kernel_directly:
            if not is_linux:
                kernel_commandline.append("autoboot_delay=0")  # Avoid the 10-second delay when booting
            qemu_args.append("-append")
            qemu_args.append(" ".join(kernel_commandline))
        else:
            warn("Cannot pass kernel command line when booting disk image: ", kernel_commandline)
    success("Starting QEMU: ", " ".join(qemu_args))
    qemu_starttime = datetime.datetime.now()
    if _SSH_SOCKET_PLACEHOLDER is not None:
        _SSH_SOCKET_PLACEHOLDER.close()
    qemu_cls = linux.QemuLinuxInstance if is_linux else QemuFreeBSDInstance
    if get_global_config().pretend:
        qemu_cls = FakeQemuSpawn
    child = qemu_cls(
        qemu_options,
        qemu_args[0],
        qemu_args[1:],
        ssh_port=ssh_port,
        ssh_pubkey=ssh_pubkey,
        encoding="utf-8",
        echo=False,
        timeout=60,
    )
    # child.logfile=sys.stdout.buffer
    child.shared_dirs = shared_dirs
    if QEMU_LOGFILE:
        child.logfile = QEMU_LOGFILE.open("w", encoding="utf-8")
    else:
        child.logfile_read = sys.stdout

    if is_linux:
        linux.boot_and_login_linux(child, starttime=qemu_starttime)
    else:
        expected_kernel_abi_arg_to_regex = {
            "hybrid": freebsd.CHERI_HYBRID_KERNEL_MSG,
            "purecap": freebsd.CHERI_PURECAP_KERNEL_MSG,
            "purecap-benchmark": freebsd.CHERI_PURECAP_BENCHMARK_KERNEL_MSG,
            "any": None,
        }
        freebsd.boot_and_login_freebsd(
            child,
            starttime=qemu_starttime,
            kernel_init_only=kernel_init_only,
            network_iface=qemu_options.network_interface_name(),
            expected_kernel_abi_msg=expected_kernel_abi_arg_to_regex[expected_kernel_abi],
            loader_kernel_dir=loader_kernel_dir,
        )
    return child


def _do_test_setup(
    qemu: QemuGuestInstance,
    args: argparse.Namespace,
    test_archives: "list[Path]",
    test_ld_preload_files: "list[Path]",
    test_setup_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], None]]" = None,
):
    # Check the target OS rather than isinstance(qemu, linux.QemuLinuxInstance): in --pretend mode
    # qemu is always a FakeQemuSpawn regardless of guest OS, so isinstance() would never match.
    is_linux_guest = qemu.xtarget.target_info_cls.is_linux()
    shared_dirs = qemu.shared_dirs
    setup_tests_starttime = datetime.datetime.now()
    if not is_linux_guest:
        # Print a backtrace and drop into the debugger on panic
        qemu.run("sysctl debug.debugger_on_panic=1; sysctl debug.trace_on_panic=1")
        # Enable userspace CHERI exception logging to aid debugging
        qemu.run("sysctl machdep.log_user_cheri_exceptions=1 || sysctl machdep.log_cheri_exceptions=1")
        if args.enable_coredumps:
            for shared_dir in shared_dirs:
                # If we are mounting /build or /test-results then set kern.corefile to point there:
                if not shared_dir.readonly and shared_dir.in_target in ["/build", "/test-results"]:
                    qemu.run("sysctl kern.corefile=" + shared_dir.in_target + "/%N.%P.core")
                    break
                else:
                    # Otherwise, place coredumps on tmpfs to avoid slowing down the tests.
                    qemu.run("sysctl kern.corefile=/tmp/%N.%P.core")
            qemu.run("sysctl kern.coredump=1")
        else:
            # If not, disable coredumps, otherwise we get no space left on device errors
            qemu.run("sysctl kern.coredump=0")
        # ensure that /usr/local exists and if not create it as a tmpfs (happens in the minimal image)
        # However, don't do it on the full image since otherwise we would install kyua to the tmpfs on /usr/local
        # We can differentiate the two by checking if /boot/kernel/kernel exists since it will be missing in the
        # minimal image
        qemu.run(
            "if [ ! -e /boot/kernel/kernel ]; then mkdir -p /usr/local && "
            "mount -t tmpfs -o size=300m tmpfs /usr/local; fi"
        )
        # Or this: if [ "$(ls -A $DIR)" ]; then echo "Not Empty"; else echo "Empty"; fi
        qemu.run("if [ ! -e /opt ]; then mkdir -p /opt && mount -t tmpfs -o size=500m tmpfs /opt; fi")
        qemu.run("df -ih")
    info("\nWill transfer the following archives: ", test_archives)

    def do_scp(src, dst="/"):
        # CVE-2018-20685 -> Can no longer use '.' See
        # https://superuser.com/questions/1403473/scp-error-unexpected-filename
        scp_cmd = [
            "scp",
            "-B",
            "-r",
            "-P",
            str(qemu.ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(qemu.ssh_private_key),
            str(src),
            "root@localhost:" + dst,
        ]
        # use script for a fake tty to get progress output from scp
        if sys.platform.startswith("linux"):
            scp_cmd = ["script", "--quiet", "--return", "--command", " ".join(scp_cmd), "/dev/null"]
        run_host_command(scp_cmd, cwd=str(src))

    for archive in test_archives:
        if shared_dirs:
            run_host_command(["tar", "xf", str(archive), "-C", str(shared_dirs[0].hostdir)])
        else:
            # Extract to temporary directory and scp over
            with tempfile.TemporaryDirectory(dir=os.getcwd(), prefix="test_files_") as tmp:
                run_host_command(["tar", "xf", str(archive), "-C", tmp])
                run_host_command(["ls", "-la"], cwd=tmp)
                do_scp(tmp)
    ld_preload_target_paths = []
    for lib in test_ld_preload_files:
        assert isinstance(lib, Path)
        if shared_dirs:
            run_host_command(["mkdir", "-p", str(shared_dirs[0].hostdir) + "/preload"])
            run_host_command(["cp", "-v", str(lib.absolute()), str(shared_dirs[0].hostdir) + "/preload"])
            ld_preload_target_paths.append(str(Path(shared_dirs[0].in_target, "preload", lib.name)))
        else:
            qemu.run("mkdir -p /tmp/preload")
            do_scp(str(lib), "/tmp/preload/" + lib.name)
            ld_preload_target_paths.append(str(Path("/tmp/preload", lib.name)))

    if not is_linux_guest:
        # List all available file system modules to check for 9P availability
        run_guest_command(qemu, "find $(sysctl -n kern.module_path | tr ';' ' ') -maxdepth 1 -name \"*fs.ko\" -print")

    for index, d in enumerate(shared_dirs):
        qemu.run(f"mkdir -p '{d.in_target}'")
        share_name = f"qemu{index + 1}"
        assert d.mounted is False
        if is_linux_guest:
            # Only 9pfs is supported for Linux guests (assumed to always be available; no SMB fallback).
            linux.mount_via_9p_linux(d, qemu, share_name)
        else:
            # Try p9fs first but if it fails, fall back to using SMBv1
            if qemu.can_use_p9fs:
                if not freebsd.mount_via_p9fs(d, qemu, share_name):
                    # Fallback to smbfs on this iteration and don't try p9fs again
                    qemu.can_use_p9fs = False
                    info("9P mount failed, falling back to SMB mount.")
            if qemu.can_use_smb:
                if not freebsd.mount_via_smb(d, qemu, share_name):
                    qemu.can_use_smb = False
        if not d.mounted:
            qemu.shared_mount_failed = True
            failure(f"Failed to mount host directory {d.hostdir}.", exit=False)

    if test_archives and not get_global_config().pretend:
        time.sleep(5)  # wait 5 seconds to make sure the disks have synced
    # See how much space we have after running scp
    qemu.run("df -h")
    # ensure that /tmp is world-writable
    qemu.run("chmod 777 /tmp")

    for lib in ld_preload_target_paths:
        # Ensure that the libraries exist
        checked_run_guest_command(qemu, f"test -x '{lib}'")
    if ld_preload_target_paths:
        checked_run_guest_command(
            qemu, "export '{}={}'".format(args.test_ld_preload_variable, ":".join(ld_preload_target_paths))
        )
        if args.test_ld_preload_variable == "LD_64C_PRELOAD":
            checked_run_guest_command(
                qemu, "export '{}={}'".format("LD_CHERI_PRELOAD", ":".join(ld_preload_target_paths))
            )

    if args.extra_library_paths:
        prepend_ld_library_path(qemu, ":".join(args.extra_library_paths))
    success("Preparing test enviroment took ", datetime.datetime.now() - setup_tests_starttime)
    if test_setup_function:
        setup_tests_starttime = datetime.datetime.now()
        test_setup_function(qemu, args)
        success("Additional test enviroment setup took ", datetime.datetime.now() - setup_tests_starttime)


def runtests(
    qemu: QemuGuestInstance,
    args: argparse.Namespace,
    test_archives: "list[Path]",
    test_ld_preload_files: "list[Path]",
    test_setup_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], None]]" = None,
    test_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], bool]]" = None,
) -> bool:
    try:
        _do_test_setup(qemu, args, test_archives, test_ld_preload_files, test_setup_function)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        failure("Got exception while preparing test environment:", e, exit=True)
        return False

    if args.test_environment_only:
        success("Test environment set up. Skipping tests due to --test-environment-only")
        return True

    run_tests_starttime = datetime.datetime.now()
    # Run the tests (allowing custom test functions)
    if test_function:
        result = False
        try:
            result = test_function(qemu, args)
        except KeyboardInterrupt:
            result = False
            failure("Got CTRL+C while running tests", exit=False)
        except CommandFailedError as e:
            testtime = datetime.datetime.now() - run_tests_starttime
            failure("Command failed after ", testtime, " while running tests: ", str(e), "\n", str(qemu), exit=False)
        testtime = datetime.datetime.now() - run_tests_starttime
        if result is True:
            success("Running tests took ", testtime)
        else:
            failure("Tests failed after ", testtime, exit=False)
        return result

    test_command = args.test_command
    timeout = args.test_timeout
    qemu.sendline(test_command + " ;if test $? -eq 0; then echo 'TESTS' 'COMPLETED'; else echo 'TESTS' 'FAILED'; fi")
    i = qemu.expect([pexpect.TIMEOUT, "TESTS COMPLETED", "TESTS UNSTABLE", "TESTS FAILED"], timeout=timeout)
    testtime = datetime.datetime.now() - run_tests_starttime
    if i == 0:  # Timeout
        return failure(
            "timeout after ", testtime, "waiting for tests (command='", test_command, "'): ", str(qemu), exit=False
        )
    elif i == 1 or i == 2:
        if i == 2:
            success("===> Tests completed (but with FAILURES)!")
        else:
            success("===> Tests completed!")
        success("Running tests took ", testtime)
        qemu.run("df -h", expected_output="/opt")  # see how much space we have now
        return True
    else:
        return failure("error after ", testtime, "while running tests : ", str(qemu), exit=False)


def get_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--architecture",
        help="CPU architecture to be used for this test",
        required=True,
        choices=[x for x in SUPPORTED_ARCHITECTURES.keys()],
    )
    parser.add_argument("--qemu-cmd", "--qemu", help="Path to QEMU (default: find matching on in $PATH)", default=None)
    parser.add_argument("--qemu-smp", "--smp", type=int, help="Run QEMU with SMP", default=None)
    parser.add_argument("--kernel", default=None)
    parser.add_argument("--bios", default=None)
    parser.add_argument("--disk-image", default=None)
    parser.add_argument("--initramfs", default=None, help="Path to an initramfs image (Linux guests only)")
    parser.add_argument(
        "--minimal-image",
        action="store_true",
        help="Set this if tests are being run on the minimal disk image rather than the full one",
    )
    parser.add_argument("--extract-images-to", help="Path where the compressed images should be extracted to")
    parser.add_argument("--reuse-image", action="store_true")
    parser.add_argument("--keep-compressed-images", action="store_true", default=True, dest="keep_compressed_images")
    parser.add_argument("--no-keep-compressed-images", action="store_false", dest="keep_compressed_images")
    parser.add_argument(
        "--write-disk-image-changes",
        default=False,
        action="store_true",
        help="Commit changes made to the disk image (by default the image is immutable)",
    )
    parser.add_argument("--no-write-disk-image-changes", action="store_false", dest="write_disk_image_changes")
    parser.add_argument(
        "--trap-on-unrepresentable", action="store_true", help="CHERI trap on unrepresentable caps instead of detagging"
    )
    parser.add_argument("--ssh-key", "--test-ssh-key", default=default_ssh_key())
    parser.add_argument("--ssh-port", type=int, default=None)
    parser.add_argument("--use-smb-instead-of-ssh", action="store_true")
    parser.add_argument(
        "--shared-mount-directory",
        "--smb-mount-directory",
        metavar="HOST_PATH:IN_TARGET",
        help="Share a host directory with the QEMU guest via 9pfs/smb. This option can be passed multiple "
        "times to share more than one directory. The argument should be colon-separated as follows: "
        "'<HOST_PATH>:<EXPECTED_PATH_IN_TARGET>'. Appending '@ro' to HOST_PATH will cause the directory "
        "to be mapped as a read-only share.",
        action="append",
        dest="shared_mount_directories",
        type=parse_smb_mount,
        default=[],
    )
    parser.add_argument("--test-archive", "-t", action="append", nargs=1)
    parser.add_argument("--test-command", "-c")
    parser.add_argument(
        "--test-ld-preload",
        action="append",
        nargs=1,
        metavar="LIB",
        help="Copy LIB to the guest and LD_PRELOAD it before running tests",
    )
    parser.add_argument(
        "--extra-library-path",
        action="append",
        dest="extra_library_paths",
        metavar="DIR",
        help="Add DIR as an additional LD_LIBRARY_PATH before running tests",
    )
    parser.add_argument(
        "--test-ld-preload-variable",
        type=str,
        default=None,
        help="The environment variable to set to LD_PRELOAD a library. should be set to either "
        "LD_PRELOAD or LD_64C_PRELOAD",
    )
    parser.add_argument("--test-timeout", "-tt", type=int, default=60 * 60, help="Timeout in seconds for running tests")
    parser.add_argument("--qemu-logfile", help="File to write all interactions with QEMU to", type=Path)
    parser.add_argument(
        "--test-environment-only",
        action="store_true",
        help="Setup mount paths + SSH for tests but don't actually run the tests (implies --interact)",
    )
    parser.add_argument(
        "--skip-ssh-setup",
        action="store_true",
        help="Don't start sshd on boot. Saves a few seconds of boot time if not needed.",
    )
    parser.add_argument(
        "--pretend", "-p", action="store_true", help="Don't actually boot the guest, just print what would happen"
    )
    parser.add_argument("--interact", "-i", action="store_true")
    parser.add_argument(
        "--interact-on-kernel-panic",
        action="store_true",
        help="Instead of exiting on kernel panic start interacting with QEMU",
    )
    parser.add_argument("--test-kernel-init-only", action="store_true")
    parser.add_argument("--enable-coredumps", action="store_true", dest="enable_coredumps", default=False)
    parser.add_argument("--disable-coredumps", action="store_false", dest="enable_coredumps")
    parser.add_argument(
        "--alternate-kernel-rootfs-path",
        type=Path,
        default=None,
        help="Path relative to the disk image pointing to the directory "
        + "containing the alternate kernel to run and related kernel modules",
    )
    parser.add_argument(
        "--expected-kernel-abi",
        choices=["any", "hybrid", "purecap", "purecap-benchmark"],
        default="any",
        help="The kernel kind that is expected ('any' to skip checks)",
    )
    # Ensure that we don't get a race when running multiple shards:
    # If we extract the disk image at the same time we might spawn QEMU just between when the
    # value extracted by one job is unlinked and when it is replaced with a new file
    parser.add_argument("--internal-kernel-override", help=argparse.SUPPRESS)
    parser.add_argument("--internal-disk-image-override", help=argparse.SUPPRESS)
    return parser


def _main(
    test_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], bool]]" = None,
    test_setup_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], None]]" = None,
    argparse_setup_callback: "Optional[Callable[[argparse.ArgumentParser], None]]" = None,
    argparse_adjust_args_callback: "Optional[Callable[[argparse.Namespace], None]]" = None,
):
    parser = get_argument_parser()
    if argparse_setup_callback:
        argparse_setup_callback(parser)
    try:
        # noinspection PyUnresolvedReferences
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()
    init_global_config(ConfigBase(pretend=args.pretend, verbose=True, quiet=False, force=False))
    if args.ssh_port is None:
        temp_ssh_port = find_free_port()
        args.ssh_port = temp_ssh_port.port
        # keep the socket open until just before we start QEMU to prevent other parallel jobs from reusing the same port
        global _SSH_SOCKET_PLACEHOLDER  # noqa: PLW0603
        _SSH_SOCKET_PLACEHOLDER = temp_ssh_port.socket
    if args.use_smb_instead_of_ssh:
        # Skip all ssh setup by default if we are using smb instead
        args.skip_ssh_setup = True
    if args.internal_kernel_override:
        args.kernel = args.internal_kernel_override
    if args.internal_disk_image_override:
        args.disk_image = args.internal_disk_image_override
        # Allow running multiple jobs in parallel by using the -snaptshot QEMU option
        assert not args.write_disk_image_changes, "Should not be writing changes when running sharded tests!"
    if args.test_environment_only:
        args.interact = True
    xtarget = SUPPORTED_ARCHITECTURES.get(args.architecture, None)
    if xtarget is None:
        failure("Invalid architecture", args.architecture, exit=True)
    assert isinstance(xtarget, CrossCompileTarget)
    args.xtarget = xtarget
    if argparse_adjust_args_callback:
        argparse_adjust_args_callback(args)
    qemu_options = QemuOptions(xtarget)
    if args.qemu_cmd is not None:
        if not Path(args.qemu_cmd).exists():
            failure("ERROR: Cannot find QEMU binary ", args.qemu_cmd, " doesn't exist", exit=True)
        args.qemu_cmd = Path(args.qemu_cmd).absolute()
    else:
        args.qemu_cmd = qemu_options.get_qemu_binary()
        if args.qemu_cmd is None:
            failure("ERROR: Cannot find QEMU binary for target ", qemu_options.xtarget, exit=True)

    if args.interact_on_kernel_panic:
        _common.INTERACT_ON_KERNEL_PANIC = True
    global QEMU_LOGFILE  # noqa: PLW0603
    if args.qemu_logfile:
        QEMU_LOGFILE = args.qemu_logfile

    starttime = datetime.datetime.now()

    # validate args:
    test_archives: list[Path] = []
    test_ld_preload_files: list[Path] = []
    if not args.use_smb_instead_of_ssh and not args.skip_ssh_setup:
        if args.ssh_key is None:
            failure(
                "No SSH key specified, but test script needs SSH. Please pass --test-ssh-key=/path/to/id_foo.pub",
                exit=True,
            )
        ssh_key_path = Path(typing.cast(str, args.ssh_key))
        if not ssh_key_path.exists():
            failure("Specified SSH key do not exist: ", args.ssh_key, exit=True)
        if ssh_key_path.suffix != ".pub":
            failure("--ssh-key should point to the public key and not ", args.ssh_key, exit=True)
    if args.test_archive or args.test_ld_preload:
        if args.use_smb_instead_of_ssh and not args.shared_mount_directories:
            failure("--shared-mount-directory is required if ssh is disabled", exit=True)

        if args.test_archive:
            info("Using the following test archives: ", args.test_archive)
            for test_archive in args.test_archive:
                if isinstance(test_archive, list):
                    test_archive = test_archive[0]
                if not Path(test_archive).exists():
                    failure("Test archive is missing: ", test_archive, exit=True)
                if not test_archive.endswith(".tar.xz"):
                    failure("Currently only .tar.xz archives are supported", exit=True)
                test_archives.append(Path(test_archive))
        elif args.test_ld_preload:
            info("Preloading the following libraries: ", args.test_ld_preload)
            if not args.test_ld_preload_variable:
                failure("--test-ld-preload-variable must be set of --test-ld-preload is set!", exit=True)

            for lib in args.test_ld_preload:
                if isinstance(lib, list):
                    lib = lib[0]
                if not Path(lib).exists():
                    failure("PRELOAD library is missing: ", lib, exit=True)
                test_ld_preload_files.append(Path(lib).resolve())

        if not args.test_command:
            failure("WARNING: No test command specified, tests will fail", exit=False)
            args.test_command = "false"

    force_decompression: bool = not args.reuse_image
    keep_compressed_images: bool = args.keep_compressed_images
    if args.extract_images_to:
        extract_path = Path(args.extract_images_to)
        extract_path.mkdir(parents=True, exist_ok=True)
        new_kernel_path = extract_path / Path(args.kernel).name
        shutil.copy(args.kernel, new_kernel_path)
        args.kernel = new_kernel_path
        if args.disk_image:
            new_image_path = os.path.join(args.extract_images_to, Path(args.disk_image).name)
            shutil.copy(args.disk_image, new_image_path)
            args.disk_image = new_image_path

        force_decompression = True
        keep_compressed_images = False
    kernel = None
    if args.kernel is not None:
        kernel = maybe_decompress(
            Path(args.kernel), force_decompression, keep_archive=keep_compressed_images, args=args, what="kernel"
        )
    diskimg = None
    if args.disk_image:
        diskimg = maybe_decompress(
            Path(args.disk_image),
            force_decompression,
            keep_archive=keep_compressed_images,
            args=args,
            what="disk image",
        )

    boot_starttime = datetime.datetime.now()
    assert args.qemu_cmd is not None
    qemu = boot_guest(
        qemu_options,
        qemu_command=args.qemu_cmd,
        kernel_image=kernel,
        disk_image=diskimg,
        ssh_port=args.ssh_port,
        ssh_pubkey=Path(args.ssh_key) if args.ssh_key is not None else None,
        shared_dirs=args.shared_mount_directories,
        kernel_init_only=args.test_kernel_init_only,
        smp_args=["-smp", str(args.qemu_smp)] if args.qemu_smp else [],
        trap_on_unrepresentable=args.trap_on_unrepresentable,
        skip_ssh_setup=args.skip_ssh_setup,
        bios_path=args.bios,
        write_disk_image_changes=args.write_disk_image_changes,
        boot_alternate_kernel_dir=args.alternate_kernel_rootfs_path,
        expected_kernel_abi=args.expected_kernel_abi,
        initramfs_image=Path(args.initramfs) if args.initramfs else None,
    )
    success("Booting guest took: ", datetime.datetime.now() - boot_starttime)

    tests_okay = True
    if (test_archives or args.test_command or test_function) and not args.test_kernel_init_only:
        # noinspection PyBroadException
        try:
            if not args.skip_ssh_setup:
                setup_ssh_starttime = datetime.datetime.now()
                setup_ssh_for_root_login(qemu)
                info("Setting up SSH took: ", datetime.datetime.now() - setup_ssh_starttime)
            tests_okay = runtests(
                qemu,
                args,
                test_archives=test_archives,
                test_function=test_function,
                test_setup_function=test_setup_function,
                test_ld_preload_files=test_ld_preload_files,
            )
        except CommandFailedError as e:
            failure("Command failed while runnings tests: ", str(e), "\n", str(qemu), exit=False)
            traceback.print_exc(file=sys.stderr)
            tests_okay = False
        except KeyboardInterrupt:
            failure("Tests interrupted!!!", exit=False)
            tests_okay = False

    if args.interact:
        success("===> Interacting with the guest, use CTRL+A,x to exit")
        # interact() prints all input+output -> disable logfile
        qemu.logfile = None
        qemu.logfile_read = None
        qemu.logfile_send = None
        while True:
            try:
                qemu.should_quit = True
                if not qemu.isalive():
                    break
                qemu.interact()
            except KeyboardInterrupt:
                continue

    success("===> DONE")
    info("Total execution time: ", datetime.datetime.now() - starttime)
    if not tests_okay:
        failure("ERROR: Some tests failed!", exit=False)
        sys.exit(2)  # different exit code for test failures


def main(
    test_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], bool]]" = None,
    test_setup_function: "Optional[Callable[[QemuGuestInstance, argparse.Namespace], None]]" = None,
    argparse_setup_callback: "Optional[Callable[[argparse.ArgumentParser], None]]" = None,
    argparse_adjust_args_callback: "Optional[Callable[[argparse.Namespace], None]]" = None,
):
    # Some programs (such as QEMU) can mess up the TTY state if they don't exit cleanly
    with keep_terminal_sane():
        run_and_kill_children_on_exit(
            lambda: _main(
                test_function=test_function,
                test_setup_function=test_setup_function,
                argparse_setup_callback=argparse_setup_callback,
                argparse_adjust_args_callback=argparse_adjust_args_callback,
            )
        )


if __name__ == "__main__":
    main()
