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
# Guest-OS-agnostic pieces of the pexpect-driven boot/test automation: shared
# spawn/instance base classes, logging helpers, and generic command execution.
# FreeBSD- and Linux-specific behaviour lives in freebsd.py/linux.py.
#
# This module must not import anything from the rest of the boot_automation
# package (only from pycheribuild/3rdparty) to avoid a circular import with
# freebsd.py/linux.py, which import from here.
import contextlib
import datetime
import re
import shlex
import signal
import subprocess
import sys
import time
import typing
from pathlib import Path
from typing import Optional, Sequence, Union

import pexpect

from ..colour import AnsiColour, coloured
from ..config.target_info import CrossCompileTarget
from ..processutils import commandline_to_str
from ..qemu_utils import QemuOptions
from ..utils import get_global_config

# Similar approach to pexpect.replwrap:
# If the user runs 'env', the value of PS1 will be in the output. To avoid seeing that as the next prompt,
# we'll embed the marker characters# for invisible characters in the prompt; these show up when inspecting the
# environment variable, but not when bash displays the prompt.
# Unfortunately FreeBSD sh doesn't handle '\\[\\]', so we rely on FreeBSD sh PS1/PS2 mapping double backslash to
# single backslash. If we embed that in the middle of the prompt string, the regexes won't match for 'env' output.
PEXPECT_PROMPT = "[PEXPECT\\PROMPT]>"
PEXPECT_CONTINUATION_PROMPT = "[++PEXPECT\\PROMPT++]"
PEXPECT_PROMPT_SET_STR = PEXPECT_PROMPT.replace("\\", "\\\\")
PEXPECT_CONTINUATION_PROMPT_SET_STR = PEXPECT_CONTINUATION_PROMPT.replace("\\", "\\\\")
PEXPECT_PROMPT_RE = re.escape(PEXPECT_PROMPT)
PEXPECT_CONTINUATION_PROMPT_RE = re.escape(PEXPECT_CONTINUATION_PROMPT)

# /bin/sh prompt used by both FreeBSD sh and busybox ash
INITIAL_PROMPT_SH = "# "

CHERI_TRAP_MIPS = re.compile(r"USER_CHERI_EXCEPTION: pid \d+ tid \d+ \(.+\)")
CHERI_TRAP_RISCV = re.compile(r"pid \d+ tid \d+ \(.+\), uid \d+: CHERI fault \(type 0x")
FATAL_ERROR_MESSAGES = [CHERI_TRAP_MIPS, CHERI_TRAP_RISCV]

SH_PROGRAM_NOT_FOUND = re.compile(r"/bin/sh: [/\w_-]+: not found")
RTLD_DSO_NOT_FOUND = re.compile(r'ld-elf[\w_-]*.so.1: Shared object ".+" not found, required by ".+"')

INTERACT_ON_KERNEL_PANIC: bool = False


class PretendSpawn(pexpect.spawn):
    def __init__(self, command, args, **kwargs):
        # Just start cat for --pretend mode
        kwargs["timeout"] = 1
        super().__init__("cat", use_poll=True, **kwargs)
        self.cmd = [command, *args]
        info("Spawning (fake) ", coloured(AnsiColour.yellow, commandline_to_str(self.cmd)))

    def expect(self, *args, pretend_result=None, **kwargs):
        args_list = args[0]
        assert isinstance(args_list, list)
        if pretend_result:
            return pretend_result
        # Never return TIMEOUT in pretend mode
        for i, v in enumerate(args_list):
            if i != pexpect.TIMEOUT:
                return i
        return 0

    def expect_exact(self, pattern_list, pretend_result=None, **kw):
        if pretend_result:
            return pretend_result
        # Never return TIMEOUT in pretend mode
        for i, v in enumerate(pattern_list):
            if i != pexpect.TIMEOUT:
                return i
        return 0

    def flush(self):
        pass

    def wait(self):
        info("Exiting (fake) ", coloured(AnsiColour.yellow, commandline_to_str(self.cmd)))

    def interact(self, escape_character=chr(29), input_filter=None, output_filter=None):
        info("Interacting with (fake) ", coloured(AnsiColour.yellow, commandline_to_str(self.cmd)))

    def sendcontrol(self, char):
        info(
            "Sending ",
            coloured(AnsiColour.yellow, "CTRL+", char),
            coloured(AnsiColour.blue, " to (fake) "),
            coloured(AnsiColour.yellow, commandline_to_str(self.cmd)),
        )

    def sendline(self, s=""):
        info(
            "Sending ",
            coloured(AnsiColour.yellow, s),
            coloured(AnsiColour.blue, " to (fake) "),
            coloured(AnsiColour.yellow, commandline_to_str(self.cmd)),
        )
        super().sendline(s)


class CommandFailedError(Exception):
    def __init__(self, *args, execution_time: datetime.timedelta):
        super().__init__(*args)
        self.execution_time = execution_time

    def __str__(self):
        return "".join(map(str, self.args))


class CommandTimeoutError(CommandFailedError):
    pass


class MatchedErrorOutputError(CommandFailedError):
    pass


class SharedMount:
    def __init__(self, hostdir: Path, readonly: bool, in_target: str):
        self.readonly = readonly
        self.hostdir = Path(hostdir).absolute()
        self.in_target = in_target
        self.mounted = False

    @property
    def qemu_arg(self) -> str:
        if self.readonly:
            return str(self.hostdir) + "@ro"
        return str(self.hostdir)

    def __repr__(self):
        return f"<{self.hostdir} ({'ro' if self.readonly else 'rw'}) -> {self.in_target}>"


def parse_smb_mount(arg: str):
    if ":" not in arg:
        failure("Invalid smb_mount string '", arg, "'. Expected format is <HOST_PATH>:<PATH_IN_TARGET>", exit=True)
    host, target = arg.split(":", 2)
    readonly = False
    if host.endswith("@ro"):
        host = host[:-3]
        readonly = True
    return SharedMount(Path(host), readonly, target)


if typing.TYPE_CHECKING:
    MixinBase = pexpect.spawn
else:
    MixinBase = object
PatternListType = Sequence[Union[str, typing.Pattern, typing.Type[pexpect.ExceptionPexpect]]]


class GuestSpawnMixin(MixinBase):
    EXIT_ON_KERNEL_PANIC = True
    # Guest-OS-specific subclasses (see freebsd.py/linux.py) must override this with their own panic patterns.
    PANIC_REGEXES: "typing.ClassVar[PatternListType]" = []

    def handle_kernel_panic(self):
        failure(
            "Kernel panic detected but no panic handler is configured for this guest",
            exit=self.EXIT_ON_KERNEL_PANIC,
        )

    def expect_exact_ignore_panic(self, patterns, *, timeout: int):
        return super().expect_exact(patterns, timeout=timeout)

    def expect(
        self,
        patterns: PatternListType,
        timeout=-1,
        pretend_result=None,
        ignore_timeout=False,
        log_patterns=True,
        timeout_msg="timeout",
        **kwargs,
    ) -> int:
        assert isinstance(patterns, list), "expected list and not " + str(patterns)
        if log_patterns:
            info("Expecting regex ", coloured(AnsiColour.cyan, str(patterns)))
        return self._expect_and_handle_panic_impl(
            patterns, timeout_msg, ignore_timeout=ignore_timeout, timeout=timeout, expect_fn=super().expect, **kwargs
        )

    def expect_exact(
        self,
        pattern_list: PatternListType,
        timeout=-1,
        pretend_result=None,
        ignore_timeout=False,
        log_patterns=True,
        timeout_msg="timeout",
        **kwargs,
    ):
        assert isinstance(pattern_list, list), "expected list and not " + str(pattern_list)
        if log_patterns:
            info("Expecting literal ", coloured(AnsiColour.blue, str(pattern_list)))
        return self._expect_and_handle_panic_impl(
            pattern_list,
            timeout_msg,
            timeout=timeout,
            ignore_timeout=ignore_timeout,
            expect_fn=super().expect_exact,
            **kwargs,
        )

    def expect_prompt(self, timeout=-1, timeout_msg="timeout waiting for prompt", ignore_timeout=False, **kwargs):
        result = self.expect_exact(
            [PEXPECT_PROMPT], timeout=timeout, timeout_msg=timeout_msg, ignore_timeout=ignore_timeout, **kwargs
        )
        time.sleep(0.05)  # give QEMU a bit of time after printing the prompt (otherwise we might lose some input)
        return result

    def _expect_and_handle_panic_impl(
        self, options: PatternListType, timeout_msg, *, ignore_timeout=True, expect_fn, timeout, **kwargs
    ) -> int:
        panic_regexes = list(self.PANIC_REGEXES)
        for i in panic_regexes:
            assert i not in options
        try:
            i = expect_fn(list(options) + panic_regexes, timeout=timeout, **kwargs)
            if i > len(options):
                self.handle_kernel_panic()
                if INTERACT_ON_KERNEL_PANIC:
                    info("Interating with QEMU due to --interact-on-kernel-panic")
                    self.interact()
                failure("EXITING DUE TO KERNEL PANIC!", exit=self.EXIT_ON_KERNEL_PANIC)
            return i
        except pexpect.TIMEOUT as e:
            failure(timeout_msg, " after ", timeout if timeout > 0 else self.timeout, " seconds", exit=False)
            if ignore_timeout:
                info(str(e))
                return -1
            else:
                raise e

    def run(
        self,
        cmd: str,
        *,
        expected_output=None,
        error_output=None,
        cheri_trap_fatal=True,
        ignore_cheri_trap=False,
        timeout=600,
    ):
        run_guest_command(
            self,
            cmd,
            expected_output=expected_output,
            error_output=error_output,
            cheri_trap_fatal=cheri_trap_fatal,
            ignore_cheri_trap=ignore_cheri_trap,
            timeout=timeout,
        )

    def checked_run(
        self, cmd: str, *, timeout=600, ignore_cheri_trap=False, error_output: "Optional[str]" = None, **kwargs
    ):
        checked_run_guest_command(
            self, cmd, timeout=timeout, ignore_cheri_trap=ignore_cheri_trap, error_output=error_output, **kwargs
        )


class GuestInstance(GuestSpawnMixin, pexpect.spawn):
    def __init__(self, xtarget: CrossCompileTarget, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.xtarget = xtarget
        self.sendchunksize = 100  # sleep after 100 sent chars


class QemuGuestInstance(GuestInstance):
    EXIT_ON_KERNEL_PANIC = True
    shared_dirs: "list[SharedMount]"
    flush_interval = None

    def __init__(self, qemu_config: QemuOptions, *args, ssh_port: Optional[int], ssh_pubkey: Optional[Path], **kwargs):
        super().__init__(qemu_config.xtarget, *args, **kwargs)
        self.qemu_config = qemu_config
        self.should_quit = False
        self.ssh_port = ssh_port
        assert ssh_pubkey is None or isinstance(ssh_pubkey, Path)
        self.ssh_public_key = ssh_pubkey
        # strip the .pub from the key file
        self._ssh_private_key = Path(ssh_pubkey).with_suffix("") if ssh_pubkey else None
        self.ssh_user = "root"
        self.shared_dirs = []
        self.shared_mount_failed = False
        self.can_use_p9fs = True
        self.can_use_smb = True
        # Guest-OS-specific mount workaround cache; only meaningful for FreeBSD's p9fs mount, but
        # kept here (not on QemuFreeBSDInstance) so --pretend mode's shared FakeQemuSpawn has it too.
        self.cheribsd_issue_2617_fixed: Optional[bool] = None

    @property
    def ssh_private_key(self):
        if self._ssh_private_key is None:
            failure(
                "Attempted to use SSH without specifying a key, please pass --test-ssh-key=/path/to/id_foo.pub to "
                "cheribuild.",
                exit=True,
            )
        assert self._ssh_private_key != self.ssh_public_key, (self._ssh_private_key, "!=", self.ssh_public_key)
        return self._ssh_private_key

    @staticmethod
    def _ssh_options(use_controlmaster: bool):
        result = [
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "NoHostAuthenticationForLocalhost=yes",
            # "-o", "ConnectTimeout=20",
            # "-o", "ConnectionAttempts=2",
        ]
        if use_controlmaster:
            # XXX: always use controlmaster for faster connections?
            controlmaster_dir = Path.home() / ".ssh/controlmasters"
            controlmaster_dir.mkdir(exist_ok=True)
            result += [
                "-o",
                f"ControlPath={controlmaster_dir}/%r@%h:%p",
                "-o",
                "ControlMaster=auto",
                # Keep socket open for 10 min (600) or indefinitely (yes)
                "-o",
                "ControlPersist=600",
            ]
        return result

    def run_command_via_ssh(
        self,
        command: "list[str]",
        *,
        stdout=None,
        stderr=None,
        check=True,
        verbose=False,
        use_controlmaster=False,
        **kwargs,
    ) -> "subprocess.CompletedProcess[bytes]":
        assert self.ssh_port is not None
        ssh_command = [
            "ssh",
            "{user}@{host}".format(user=self.ssh_user, host="localhost"),
            "-p",
            str(self.ssh_port),
            "-i",
            str(self.ssh_private_key),
        ]
        if verbose:
            ssh_command.append("-v")
        ssh_command.extend(self._ssh_options(use_controlmaster=use_controlmaster))
        ssh_command.append("--")
        ssh_command.extend(command)
        print_cmd(ssh_command, **kwargs)
        return subprocess.run(ssh_command, stdout=stdout, stderr=stderr, check=check, **kwargs)

    def check_ssh_connection(self, prefix="SSH connection:"):
        connection_test_start = datetime.datetime.now(datetime.timezone.utc)
        result = self.run_command_via_ssh(
            ["echo", "connection successful"], check=True, stdout=subprocess.PIPE, verbose=True
        )
        connection_time = (datetime.datetime.now(datetime.timezone.utc) - connection_test_start).total_seconds()
        info(prefix, result.stdout)
        if result.stdout != b"connection successful\n":
            failure(prefix, " unexepected output ", result.stdout, " after ", connection_time, " seconds", exit=False)
            return False
        else:
            success(prefix, " successful after ", connection_time, " seconds")
            return True

    def scp_from_guest(self, qemu_dir: str, local_dir: Path):
        assert self.ssh_port is not None
        command = ["scp", "-P", str(self.ssh_port), "-i", str(self.ssh_private_key)]
        command.extend(self._ssh_options(use_controlmaster=False))
        command.append("{user}@{host}:{remote_dir}".format(user=self.ssh_user, host="localhost", remote_dir=qemu_dir))
        if not local_dir.parent.exists():
            failure("Parent dir does't exist: ", local_dir, exit=False)
        command.append(str(local_dir))
        run_host_command(command)

    def scp_to_guest(self, local_path: Path, qemu_path: str):
        assert self.ssh_port is not None
        command = ["scp", "-P", str(self.ssh_port), "-i", str(self.ssh_private_key)]
        command.extend(self._ssh_options(use_controlmaster=False))
        command.append(str(local_path))
        if not local_path.exists():
            failure("Path does't exist: ", local_path, exit=False)
        command.append("{user}@{host}:{remote_dir}".format(user=self.ssh_user, host="localhost", remote_dir=qemu_path))
        run_host_command(command)


# noinspection PyMethodMayBeStatic,PyUnusedLocal
class FakeQemuSpawn(QemuGuestInstance):
    def __init__(self, qemu_config: QemuOptions, *args, **kwargs):
        # Just start cat for --pretend mode
        kwargs["timeout"] = 1
        super().__init__(qemu_config, "cat", use_poll=True, **kwargs)

    def expect(self, *args, pretend_result=None, **kwargs):
        # info("Expecting", args)
        args_list = args[0]
        assert isinstance(args_list, list)
        if pretend_result:
            return pretend_result
        # Never return TIMEOUT in pretend mode
        if args_list[0] == pexpect.TIMEOUT:
            return 1
        return 0

    def expect_prompt(self, *args, **kwargs):
        info("Expecting prompt")
        return

    def flush(self):
        pass

    def run(self, cmd, **kwargs):
        run_guest_command(self, cmd, **kwargs)

    def checked_run(self, cmd, **kwargs):
        checked_run_guest_command(self, cmd, **kwargs)

    def check_ssh_connection(self, prefix="SSH connection:"):
        success(prefix, "checked SSH connection")
        return True

    def send(self, s):
        return self.stderr.write(s)

    def sendintr(self):
        self.stderr.write("^C\n")

    def interact(self, escape_character=chr(29), input_filter=None, output_filter=None):
        if self.should_quit:
            super().kill(signal.SIGTERM)
            time.sleep(0.1)
        info("Interacting (fake) ...")


def _message_prefix() -> str:
    # MESSAGE_PREFIX lives in the package __init__ (not here) since external callers such as
    # run_libcxx_tests.py set it via `boot_automation.MESSAGE_PREFIX = ...` for sharded test output;
    # importing it eagerly would just copy the value once instead of tracking further changes.
    from . import MESSAGE_PREFIX

    return MESSAGE_PREFIX


def info(*args, **kwargs):
    print(_message_prefix(), "\033[0;34m", *args, "\033[0m", file=sys.stderr, sep="", flush=True, **kwargs)


def warn(*args, **kwargs):
    print(_message_prefix(), "\033[0;35m", *args, "\033[0m", file=sys.stderr, sep="", flush=True, **kwargs)


def success(*args, **kwargs):
    print("\n", _message_prefix(), "\033[0;32m", *args, "\033[0m", sep="", file=sys.stderr, flush=True, **kwargs)


def print_cmd(cmd: "list[str]", **kwargs):
    args_str = " ".join(shlex.quote(i) for i in list(cmd))
    if kwargs:
        print("\033[0;33mRunning ", args_str, " with ", kwargs.copy(), "\033[0m", sep="", file=sys.stderr, flush=True)
    else:
        print("\033[0;33mRunning ", args_str, "\033[0m", sep="", file=sys.stderr, flush=True)


# noinspection PyShadowingBuiltins
def failure(*args, exit: bool, **kwargs):
    print("\n", _message_prefix(), "\033[0;31m", *args, "\033[0m", sep="", file=sys.stderr, flush=True, **kwargs)
    if exit:
        if get_global_config().pretend:
            print("\033[0;37mIgnored fatal error in --pretend mode\033[0m", sep="", file=sys.stderr, flush=True)
        else:
            with contextlib.suppress(Exception):
                time.sleep(1)  # to get the remaining output
            print("\033[0;37mExiting due to fatal error\033[0m", sep="", file=sys.stderr, flush=True)
            sys.exit(1)
    return False


def run_host_command(cmd: "list[str]", **kwargs):
    print_cmd(cmd, **kwargs)
    if get_global_config().pretend:
        return
    subprocess.check_call(cmd, **kwargs)


def decompress(archive: Path, force_decompression: bool, *, keep_archive=True, cmd: "list[str]") -> Path:
    result = archive.with_suffix("")
    if result.exists() and not force_decompression:
        return result
    info("Extracting ", archive)
    if keep_archive:
        cmd += ["-k"]
    run_host_command([*cmd, str(archive)])
    return result


def is_newer(path1: Path, path2: Path):
    return path1.stat().st_ctime > path2.stat().st_ctime


def maybe_decompress(
    path: Path, force_decompression: bool, keep_archive=True, args: "Optional[object]" = None, *, what: str
) -> Path:
    # drop the suffix and then try decompressing
    def bunzip(archive):
        return decompress(archive, force_decompression, cmd=["bunzip2", "-v", "-f"], keep_archive=keep_archive)

    def unxz(archive):
        return decompress(archive, force_decompression, cmd=["xz", "-d", "-v", "-f"], keep_archive=keep_archive)

    if args and getattr(args, "internal_shard", None) and not get_global_config().pretend:
        assert path.exists()

    if path.suffix == ".bz2":
        return bunzip(path)
    if path.suffix == ".xz":
        return unxz(path)

    bz2_guess = path.with_suffix(path.suffix + ".bz2")
    # try adding the archive suffix
    if bz2_guess.exists():
        if path.is_file() and is_newer(path, bz2_guess):
            info("Not Extracting ", bz2_guess, " since uncompressed image ", path, " is newer")
            return path
        info("Extracting ", bz2_guess, " since it is newer than uncompressed image ", path)
        return bunzip(bz2_guess)

    xz_guess = path.with_suffix(path.suffix + ".xz")
    if xz_guess.exists():
        if path.is_file() and is_newer(path, xz_guess):
            info("Not Extracting ", xz_guess, " since uncompressed image ", path, " is newer")
            return path
        info("Extracting ", xz_guess, " since it is newer than uncompressed image ", path)
        return unxz(xz_guess)

    if not path.exists():
        failure("Could not find " + what + " " + str(path), exit=True)
    assert get_global_config().pretend or path.exists(), path
    return path


def run_guest_command(
    qemu: GuestSpawnMixin,
    cmd: str,
    expected_output=None,
    error_output=None,
    cheri_trap_fatal=True,
    ignore_cheri_trap=False,
    timeout=60,
):
    qemu.sendline(cmd)
    # FIXME: allow ignoring CHERI traps
    if expected_output:
        qemu.expect([expected_output], timeout=timeout)

    results = [
        SH_PROGRAM_NOT_FOUND,
        RTLD_DSO_NOT_FOUND,
        pexpect.TIMEOUT,
        PEXPECT_PROMPT_RE,
        PEXPECT_CONTINUATION_PROMPT_RE,
    ]
    error_output_index = -1
    cheri_trap_indices = tuple()
    if error_output:
        error_output_index = len(results)
        results.append(error_output)
    if not ignore_cheri_trap:
        cheri_trap_indices = (len(results), len(results) + 1)
        results.append(CHERI_TRAP_MIPS)
        results.append(CHERI_TRAP_RISCV)
    starttime = datetime.datetime.now()
    i = qemu.expect(results, timeout=timeout, pretend_result=3)
    runtime = datetime.datetime.now() - starttime
    if i == 0:
        raise CommandFailedError("/bin/sh: command not found: ", cmd, execution_time=runtime)
    elif i == 1:
        raise CommandFailedError("Missing shared library dependencies: ", cmd, execution_time=runtime)
    elif i == 2:
        raise CommandTimeoutError("timeout running ", cmd, execution_time=runtime)
    elif i == 3:
        success("ran '", cmd, "' successfully (in ", runtime.total_seconds(), "s)")
    elif i == 4:
        raise CommandFailedError("Detected line continuation, cannot handle this yet! ", cmd, execution_time=runtime)
    elif i == error_output_index:
        # wait up to 20 seconds for a prompt to ensure the full output has been printed
        qemu.expect_prompt(timeout=20, ignore_timeout=True)
        qemu.flush()
        raise MatchedErrorOutputError("Matched error output ", error_output, " in ", cmd, execution_time=runtime)
    elif i in cheri_trap_indices:
        # wait up to 20 seconds for a prompt to ensure the dump output has been printed
        qemu.expect_prompt(timeout=20, ignore_timeout=True)
        qemu.flush()
        if cheri_trap_fatal:
            raise CommandFailedError("Got CHERI TRAP!", execution_time=runtime)
        else:
            failure("Got CHERI TRAP!", exit=False)


def checked_run_guest_command(
    qemu: GuestSpawnMixin,
    cmd: str,
    timeout=600,
    ignore_cheri_trap=False,
    error_output: "Optional[str]" = None,
    **kwargs,
):
    starttime = datetime.datetime.now()
    qemu.sendline(
        cmd + " ;if test $? -eq 0; then echo '__COMMAND' 'SUCCESSFUL__'; else echo '__COMMAND' 'FAILED__'; fi"
    )
    cheri_trap_indices = tuple()
    error_output_index = None
    results: PatternListType = [
        "__COMMAND SUCCESSFUL__",
        "__COMMAND FAILED__",
        PEXPECT_CONTINUATION_PROMPT_RE,
        pexpect.TIMEOUT,
    ]
    if not ignore_cheri_trap:
        cheri_trap_indices = (len(results), len(results) + 1)
        results.append(CHERI_TRAP_MIPS)  # ty:ignore[invalid-argument-type]
        results.append(CHERI_TRAP_RISCV)  # ty:ignore[invalid-argument-type]
    if error_output:
        error_output_index = len(results)
        results.append(error_output)
    i = qemu.expect(results, timeout=timeout, **kwargs)
    runtime = datetime.datetime.now() - starttime
    if i == 0:
        success("ran '", cmd, "' successfully (in ", runtime.total_seconds(), "s)")
        qemu.expect_prompt(timeout=10)
        qemu.flush()
        return True
    elif i == 2:
        raise CommandFailedError("Detected line continuation, cannot handle this yet! ", cmd, execution_time=runtime)
    elif i == 3:
        raise CommandTimeoutError(
            "timeout after ", runtime, " running '", cmd, "': ", str(qemu), execution_time=runtime
        )
    elif i in cheri_trap_indices:
        # wait up to 20 seconds for a prompt to ensure the dump output has been printed
        qemu.expect_prompt(timeout=20, ignore_timeout=True)
        qemu.flush()
        raise CommandFailedError(
            "Got CHERI trap running '", cmd, "' (after '", runtime.total_seconds(), "s)", execution_time=runtime
        )
    elif i == error_output_index:
        # wait up to 20 seconds for the shell prompt
        qemu.expect_prompt(timeout=20, ignore_timeout=True)
        qemu.flush()
        assert isinstance(error_output, str)
        raise MatchedErrorOutputError(
            "Matched error output '" + error_output + "' running '",
            cmd,
            "' (after '",
            runtime.total_seconds(),
            ")",
            execution_time=runtime,
        )
    else:
        assert i < len(results), str(i) + " >= len(" + str(results) + ")"
        raise CommandFailedError(
            "error running '", cmd, "' (after '", runtime.total_seconds(), "s)", execution_time=runtime
        )


def _set_pexpect_sh_prompt(child):
    success("===> setting PS1")
    # Make the prompt match PROMPT
    # TODO: stty rows 40 cols 500? to avoid stupid line wrapping
    # Note: it seems like sending all three at once does not always work, so we set them in reverse order.
    child.sendline("PROMPT_COMMAND=''")
    child.sendline(f"PS2='{PEXPECT_CONTINUATION_PROMPT_SET_STR}'")
    child.sendline(f"PS1='{PEXPECT_PROMPT_SET_STR}'")
    # Find the prompt
    child.expect_prompt(timeout=2 * 60)
    success("===> successfully set PS1/PS2")
