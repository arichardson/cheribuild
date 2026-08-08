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
# FreeBSD/CheriBSD-specific boot/login/mount behaviour.
import datetime
import random
import re
import shlex
import time
import typing
from pathlib import Path
from typing import Optional

import pexpect

from ._common import (
    FATAL_ERROR_MESSAGES,
    INITIAL_PROMPT_SH,
    CommandFailedError,
    GuestInstance,
    GuestSpawnMixin,
    MatchedErrorOutputError,
    PatternListType,
    QemuGuestInstance,
    _set_pexpect_sh_prompt,
    checked_run_guest_command,
    failure,
    get_global_config,
    info,
    success,
)
from ..config.compilation_targets import CompilationTargets

SUPPORTED_ARCHITECTURES = {
    x.generic_target_suffix: x
    for x in (
        CompilationTargets.CHERIBSD_RISCV_NO_CHERI,
        CompilationTargets.CHERIBSD_RISCV_HYBRID,
        CompilationTargets.CHERIBSD_RISCV_PURECAP,
        CompilationTargets.CHERIBSD_X86_64,
        CompilationTargets.CHERIBSD_AARCH64,
        CompilationTargets.CHERIBSD_MORELLO_HYBRID,
        CompilationTargets.CHERIBSD_MORELLO_PURECAP,
    )
}

# boot loader without lua: "Hit [Enter] to boot "
# menu.lua before Sep 2019: ", hit [Enter] to boot "
# menu.lua: "[Space] to pause"
AUTOBOOT_PROMPT = re.compile(r"((H|, h)it \[Enter] to boot |\[Space] to pause)")
BOOT_LOADER_PROMPT = "OK "
CHERI_HYBRID_KERNEL_MSG = "CHERI hybrid kernel."
CHERI_PURECAP_KERNEL_MSG = "CHERI pure-capability kernel."
CHERI_PURECAP_BENCHMARK_KERNEL_MSG = "CHERI pure-capability benchmark ABI kernel."

STARTING_INIT = "start_init: trying /sbin/init"
TRYING_TO_MOUNT_ROOT = re.compile(r"Trying to mount root from .+\.\.\.")
BOOT_FAILURE = "Enter full pathname of shell or RETURN for /bin/sh"
BOOT_FAILURE2 = "wait for /bin/sh on /etc/rc failed'"
BOOT_FAILURE3 = "Manual root filesystem specification:"  # rootfs mount failed
SHELL_OPEN = "exec /bin/sh"
LOGIN = "login:"
LOGIN_AS_ROOT_MINIMAL = "Logging in as root..."
INITIAL_PROMPT_CSH = re.compile(r"root@.+:.+# ")  # /bin/csh
STOPPED = "Stopped at"
PANIC = "panic: trap"
PANIC_KDB = "KDB: enter: panic"
PANIC_PAGE_FAULT = "panic: Fatal page fault at 0x"
PANIC_MORELLO_CAP_ABORT = "panic: Capability abort from kernel space"
PANIC_IN_BACKTRACE = "panic() at panic+0x"

MAX_SMBFS_RETRY = 3


class FreeBSDSpawnMixin(GuestSpawnMixin):
    PANIC_REGEXES: "typing.ClassVar[PatternListType]" = [
        PANIC,
        STOPPED,
        PANIC_KDB,
        PANIC_PAGE_FAULT,
        PANIC_MORELLO_CAP_ABORT,
        PANIC_IN_BACKTRACE,
    ]

    def handle_kernel_panic(self):
        debug_kernel_panic(self)

    def set_ld_library_path_with_sysroot(self) -> None:
        non_cheri_libdir = "lib64"
        cheri_libdir = "lib64c"
        if not self.xtarget.is_hybrid_or_purecap_cheri():
            local_dir = "usr/local"
            if self.xtarget.target_info_cls.is_cheribsd():
                local_dir += "/" + self.xtarget.generic_arch_suffix
            self.run(
                "export {var}=/{l}:/usr/{l}:/usr/local/{l}:/sysroot/{l}:/sysroot/usr/{l}:/sysroot/usr/local/{l}:"
                "/sysroot/{prefix}/{l}:${var}".format(prefix=local_dir, l="lib", var="LD_LIBRARY_PATH"),
                timeout=3,
            )
            return

        purecap_install_prefix = "usr/local/" + self.xtarget.get_cheri_purecap_target().generic_arch_suffix
        hybrid_install_prefix = "usr/local/" + self.xtarget.get_cheri_hybrid_target().generic_arch_suffix
        nocheri_install_prefix = "usr/local/" + self.xtarget.get_non_cheri_target().generic_arch_suffix

        noncheri_ld_lib_path_var = "LD_LIBRARY_PATH" if not self.xtarget.is_cheri_purecap() else "LD_64_LIBRARY_PATH"
        cheri_ld_lib_path_var = "LD_LIBRARY_PATH" if self.xtarget.is_cheri_purecap() else "LD_64C_LIBRARY_PATH"
        self.run(
            f"export {noncheri_ld_lib_path_var}=/{non_cheri_libdir}:/usr/{non_cheri_libdir}:"
            f"/usr/local/{non_cheri_libdir}:/sysroot/{non_cheri_libdir}:/sysroot/usr/{non_cheri_libdir}:"
            f"/sysroot/{hybrid_install_prefix}/lib:/sysroot/usr/local/{non_cheri_libdir}:"
            f"/sysroot/{nocheri_install_prefix}/lib:${noncheri_ld_lib_path_var}",
            timeout=3,
        )
        self.run(
            f"export {cheri_ld_lib_path_var}=/{cheri_libdir}:/usr/{cheri_libdir}:/usr/local/{cheri_libdir}:"
            f"/sysroot/{cheri_libdir}:/sysroot/usr/{cheri_libdir}:/sysroot/usr/local/{cheri_libdir}:"
            f"/sysroot/{purecap_install_prefix}/lib:${cheri_ld_lib_path_var}",
            timeout=3,
        )
        if cheri_ld_lib_path_var == "LD_64C_LIBRARY_PATH":
            self.run(
                "export {var}=/{l}:/usr/{l}:/usr/local/{l}:/sysroot/{l}:/sysroot/usr/{l}:/sysroot/usr/local/{l}:"
                "/sysroot/{prefix}/lib:${var}".format(
                    prefix=purecap_install_prefix, l=cheri_libdir, var="LD_CHERI_LIBRARY_PATH"
                ),
                timeout=3,
            )


class FreeBSDInstance(FreeBSDSpawnMixin, GuestInstance):
    pass


class QemuFreeBSDInstance(FreeBSDSpawnMixin, QemuGuestInstance):
    pass


def debug_kernel_panic(qemu: GuestSpawnMixin):
    failure("Trying to get a stack trace for kernel panic: ", qemu.match, exit=False)
    # wait up to 10 seconds for a db prompt
    # Note: this uses expect_exact_ignore_panic() to avoid infinite recursion if FreeBSD is stuck in a panic loop
    # (as is currently happening when running the test suite on RISC-V).
    patterns = [pexpect.TIMEOUT, "db> ", "KDB: stack backtrace:"]
    stack_backtrace_start_idx = 2
    i = qemu.expect_exact_ignore_panic(patterns, timeout=10)
    if i == 1:
        success("Got debugger prompt, requesting stack trace.")
        qemu.sendline("bt")
        # wait for the backtrace to be printed
        i = qemu.expect_exact_ignore_panic(patterns, timeout=30)
    if i == stack_backtrace_start_idx:
        # Already got a backtrace automatically (wait a few seconds for it to be printed)
        success("Kernel stack trace about to be printed:")
        i = qemu.expect_exact_ignore_panic(patterns, timeout=30)
        if i == stack_backtrace_start_idx:
            # Another kernel backtrace? This indicates a panic while printing the backtrace.
            # Print the first one (since it may be different), but then stop,
            i = qemu.expect_exact_ignore_panic(patterns, timeout=5)
            if i == stack_backtrace_start_idx:
                failure("Unexpected output (infinite backtrace loop?): ", qemu.match, exit=False)
    failure("GOT KERNEL PANIC!", exit=False)


def prepend_ld_library_path(qemu: GuestInstance, path: str):
    qemu.run("export LD_LIBRARY_PATH=" + path + ':$LD_LIBRARY_PATH; echo "$LD_LIBRARY_PATH"', timeout=3)
    qemu.run("export LD_64C_LIBRARY_PATH=" + path + ':$LD_64C_LIBRARY_PATH; echo "$LD_64C_LIBRARY_PATH"', timeout=3)
    qemu.run(
        "export LD_CHERI_LIBRARY_PATH=" + path + ':$LD_CHERI_LIBRARY_PATH; echo "$LD_CHERI_LIBRARY_PATH"', timeout=3
    )


def setup_ssh_for_root_login(qemu: QemuGuestInstance):
    pubkey = qemu.ssh_public_key
    assert pubkey is not None
    assert isinstance(pubkey, Path)
    # Ensure that we have permissions set up in a way so that ssh doesn't complain
    qemu.run("mkdir -p /root/.ssh && chmod 700 /root /root/.ssh")
    if get_global_config() and not pubkey.exists():
        ssh_pubkey_contents = "ssh-ed25519 AAAA Test SSH key for cheribuild"
    else:
        ssh_pubkey_contents = pubkey.read_text(encoding="utf-8").strip()
    # Handle ssh-pubkeys that might be too long to send as a single line (write 150-char chunks instead):
    chunk_size = 150
    for part in (ssh_pubkey_contents[i : i + chunk_size] for i in range(0, len(ssh_pubkey_contents), chunk_size)):
        qemu.run("printf %s " + shlex.quote(part) + " >> /root/.ssh/authorized_keys")
    # Add a final newline
    qemu.run("printf '\\n' >> /root/.ssh/authorized_keys")
    qemu.run("chmod 600 /root/.ssh/authorized_keys")
    # Allow root login
    qemu.run("echo 'PermitRootLogin without-password' >> /etc/ssh/sshd_config")
    # TODO: check for bluehive images without /sbin/service
    qemu.run("cat /root/.ssh/authorized_keys", expected_output="ssh-")
    checked_run_guest_command(qemu, "grep -n PermitRootLogin /etc/ssh/sshd_config")
    qemu.sendline("service sshd restart")
    try:
        qemu.expect(["service: not found", "Starting sshd.", "Cannot 'restart' sshd."], timeout=240)
    except pexpect.TIMEOUT:
        failure("Timed out setting up SSH keys", exit=True)
    qemu.expect_prompt(timeout=120)
    if not get_global_config().pretend:
        time.sleep(2)  # sleep for two seconds to avoid a rejection
    success("===> SSH authorized_keys set up")


def start_dhclient(qemu: GuestSpawnMixin, network_iface: str):
    success("===> Setting up QEMU networking")
    qemu.sendline(f"ifconfig {network_iface} up && dhclient {network_iface}")
    i = qemu.expect(
        [pexpect.TIMEOUT, "DHCPACK from 10.0.2.2", "dhclient already running", "interface ([\\w\\d]+) does not exist"],
        timeout=120,
    )
    if i == 0:  # Timeout
        failure("timeout awaiting dhclient ", str(qemu), exit=True)
    if i == 1:
        i = qemu.expect([pexpect.TIMEOUT, "bound to"], timeout=120)
        if i == 0:  # Timeout
            failure("timeout awaiting dhclient ", str(qemu), exit=True)
    if i == 3:
        bad_iface = qemu.match.group(1)
        qemu.expect_prompt(timeout=30)
        qemu.run("ifconfig -a")
        failure("Expected network interface ", bad_iface, " does not exist ", str(qemu), exit=True)

    success(f"===> {network_iface} bound to QEMU networking")
    qemu.expect_prompt(timeout=30)


def boot_and_login_freebsd(
    child: GuestSpawnMixin,
    *,
    starttime,
    kernel_init_only=False,
    network_iface: Optional[str],
    expected_kernel_abi_msg: Optional[str] = None,
    loader_kernel_dir: "Optional[Path]" = None,
) -> None:
    have_dhclient = False
    # ignore SIGINT for the python code, the child should still receive it
    # signal.signal(signal.SIGINT, signal.SIG_IGN)

    if kernel_init_only:
        # To test kernel startup time
        child.expect_exact(["Uptime: "], timeout=60)
        i = child.expect([pexpect.TIMEOUT, "Please press any key to reboot.", pexpect.EOF], timeout=240)
        if i == 0:
            failure("QEMU didn't exit after shutdown!", exit=False)
        return
    try:
        # BOOTVERBOSE is off for the amd64 kernel, so we don't see the STARTING_INIT message
        # TODO: it would be nice if we had a message to detect userspace startup without requiring bootverbose
        bootverbose = False
        # noinspection PyTypeChecker
        init_messages = [
            STARTING_INIT,
            CHERI_HYBRID_KERNEL_MSG,
            CHERI_PURECAP_KERNEL_MSG,
            CHERI_PURECAP_BENCHMARK_KERNEL_MSG,
            BOOT_FAILURE,
            BOOT_FAILURE2,
            BOOT_FAILURE3,
            *FATAL_ERROR_MESSAGES,
        ]
        boot_messages = [*init_messages, TRYING_TO_MOUNT_ROOT]
        loader_boot_prompt_messages = [*boot_messages, BOOT_LOADER_PROMPT]
        loader_boot_messages = [*loader_boot_prompt_messages, AUTOBOOT_PROMPT]
        i = child.expect(loader_boot_messages, timeout=20 * 60, timeout_msg="timeout before loader or kernel")
        ran_manual_boot = False
        if i >= len(boot_messages):
            # Skip 10s wait from loader(8) if we see the autoboot message
            if i == loader_boot_messages.index(AUTOBOOT_PROMPT):  # Hit Enter
                success("===> loader(8) autoboot")
                if loader_kernel_dir:
                    # Stop autoboot and enter console
                    child.send("\x1b")
                    i = child.expect(
                        loader_boot_prompt_messages, timeout=60, timeout_msg="timeout before loader prompt"
                    )
                    if i != loader_boot_prompt_messages.index(BOOT_LOADER_PROMPT):
                        failure("failed to enter boot loader prompt after stopping autoboot", exit=True)
                        # Fall through to BOOT_LOADER_PROMPT
                else:
                    child.sendline("\r")
            if i == loader_boot_messages.index(BOOT_LOADER_PROMPT):  # loader(8) prompt
                success("===> loader(8) waiting boot commands")
                # Just boot the default kernel if no alternate kernel directory is given
                child.sendline("boot {}".format(loader_kernel_dir or ""))
                ran_manual_boot = True
            i = child.expect(boot_messages, timeout=20 * 60, timeout_msg="timeout before kernel")
        if loader_kernel_dir and not ran_manual_boot:
            failure("failed to enter boot loader prompt", exit=True)

        # Check that we are booting the expected kind of CheriBSD kernel (hybrid/purecap)
        if expected_kernel_abi_msg is not None:
            if get_global_config().pretend:
                i = boot_messages.index(expected_kernel_abi_msg)
            if i == boot_messages.index(expected_kernel_abi_msg):
                success(f"Booting correct kernel ABI: {expected_kernel_abi_msg}")
            else:
                failure(
                    f"Did not find expected kernel ABI message '{expected_kernel_abi_msg}',"
                    f" got '{child.match.group(0)}' instead.",
                    exit=True,
                )
            i = child.expect(boot_messages, timeout=10 * 60, timeout_msg="timeout mounting rootfs")

        if i == boot_messages.index(TRYING_TO_MOUNT_ROOT):
            success("===> mounting rootfs")
            if bootverbose:
                i = child.expect(init_messages, timeout=5 * 60, timeout_msg="timeout before /sbin/init")
                if i != 0:  # start up scripts failed
                    failure("failed to start init", exit=True)
                userspace_starttime = datetime.datetime.now()
                success("===> init running (kernel startup time: ", userspace_starttime - starttime, ")")

        userspace_starttime = datetime.datetime.now()
        boot_expect_strings: PatternListType = [
            LOGIN,
            LOGIN_AS_ROOT_MINIMAL,
            SHELL_OPEN,
            BOOT_FAILURE,
            BOOT_FAILURE2,
            BOOT_FAILURE3,
        ]
        i = child.expect(
            [*boot_expect_strings, "DHCPACK from ", *FATAL_ERROR_MESSAGES],
            timeout=90 * 60,
            timeout_msg="timeout awaiting login prompt",
        )
        if i == len(boot_expect_strings):  # DHCPACK from
            have_dhclient = True
            success("===> got DHCPACK")
            # we have a network, keep waiting for the login prompt
            i = child.expect(
                [*boot_expect_strings, *FATAL_ERROR_MESSAGES],
                timeout=15 * 60,
                timeout_msg="timeout awaiting login prompt",
            )
        if i == boot_expect_strings.index(LOGIN):
            success("===> got login prompt")
            child.sendline("root")

            i = child.expect(
                [INITIAL_PROMPT_CSH, INITIAL_PROMPT_SH], timeout=10 * 60, timeout_msg="timeout awaiting command prompt "
            )  # give CheriABI csh 3 minutes to start
            if i == 0:  # /bin/csh prompt
                success("===> got csh command prompt, starting POSIX sh")
                # csh is weird, use the normal POSIX sh instead
                child.sendline("sh")
                i = child.expect(
                    [INITIAL_PROMPT_CSH, INITIAL_PROMPT_SH], timeout=3 * 60, timeout_msg="timeout starting /bin/sh"
                )  # give CheriABI sh 3 minutes to start
                if i == 0:  # POSIX sh with PS1 set
                    success("===> started POSIX sh (PS1 already set)")
                elif i == 1:  # POSIX sh without PS1
                    success("===> started POSIX sh (PS1 not set)")
            elif i == 1:  # /bin/sh prompt
                success("===> got /sbin/sh prompt")
            _set_pexpect_sh_prompt(child)
        elif i == boot_expect_strings.index(SHELL_OPEN):  # shell started from /etc/rc:
            child.expect_exact([INITIAL_PROMPT_SH], timeout=30)
            success("===> /etc/rc completed, got command prompt")
            _set_pexpect_sh_prompt(child)
        elif i == boot_expect_strings.index(LOGIN_AS_ROOT_MINIMAL):  # login -f root from /etc/rc:
            child.expect([INITIAL_PROMPT_SH], timeout=3 * 60, timeout_msg="timeout logging in")
            # Note: the default shell in the minimal images is csh (but without the default prompt).
            child.sendline("sh")
            child.expect([INITIAL_PROMPT_SH], timeout=3 * 60, timeout_msg="timeout starting /bin/sh")
            success("===> /etc/rc completed, got command prompt")
            _set_pexpect_sh_prompt(child)
        else:  # BOOT_FAILURE or FATAL_ERROR_MESSAGES
            # If this was a CHEIR trap, wait up to 20 seconds to ensure the dump output has been printed
            child.expect(["THIS STRING SHOULD NOT MATCH, JUST WAITING FOR 20 secs", pexpect.TIMEOUT], timeout=20)
            # If this was a failure of init, we should get a debugger backtrace
            failure("Error during boot login prompt: ", str(child), " match index=", i, exit=True)
        # set up network in case dhclient wasn't started yet
        if not have_dhclient:
            if network_iface is None:
                info("No network interface specified, not trying to start dhclient.")
            else:
                info("Did not see DHCPACK message, starting dhclient manually.")
                start_dhclient(child, network_iface=network_iface)
        success("===> booted CheriBSD (userspace startup time: ", datetime.datetime.now() - userspace_starttime, ")")
    except KeyboardInterrupt:
        failure("Keyboard interrupt during boot", exit=True)
    return


def mount_via_p9fs(d, qemu: QemuGuestInstance, share_name: str) -> bool:
    try:
        ro_flag = ",ro" if d.readonly else ""
        checked_run_guest_command(
            qemu,
            f"kldload -n virtio_p9fs && mount -t p9fs -o trans=virtio{ro_flag} {share_name} '{d.in_target}'",
        )
        d.mounted = True
    except CommandFailedError:
        d.mounted = False
        return False
    if not d.readonly:
        if qemu.cheribsd_issue_2617_fixed is None:
            try:
                # Check if we are affected by https://github.com/CTSRD-CHERI/cheribsd/issues/2617
                checked_run_guest_command(
                    qemu,
                    f"echo test > /tmp/issue_2617.txt && mv -f /tmp/issue_2617.txt {d.in_target}/issue_2617.txt",
                    pretend_result=1,
                )
                qemu.cheribsd_issue_2617_fixed = True
            except CommandFailedError:
                info("P9FS driver is not new enough to support running tests. Will unmount again.")
                qemu.cheribsd_issue_2617_fixed = False
                checked_run_guest_command(qemu, f"rm -f /tmp/issue_2617.txt {d.in_target}/issue_2617.txt")
                checked_run_guest_command(qemu, f"umount {d.in_target}")
                d.mounted = False
                return False
        if qemu.cheribsd_issue_2617_fixed is False:
            d.mounted = False
            return False
    return True


def mount_via_smb(d, qemu: QemuGuestInstance, share_name: str) -> bool:
    for trial in range(MAX_SMBFS_RETRY if not get_global_config().pretend else 1):  # maximum of 3 trials
        try:
            checked_run_guest_command(
                qemu,
                f"mount_smbfs -I 10.0.2.4 -N //10.0.2.4/{share_name} '{d.in_target}'",
                error_output="unable to open connection: syserr = ",
                pretend_result=0,
            )
            d.mounted = True
            return True
        except MatchedErrorOutputError as e:
            # If the smbfs connection timed out try once more. This can happen when multiple libc++ test jobs are
            # running on the same jenkins slaves so one of them might time out
            d.mounted = False
            failure(
                "QEMU SMBD failed to mount ",
                d.in_target,
                " after ",
                e.execution_time.total_seconds(),
                " seconds. Trying ",
                (MAX_SMBFS_RETRY - trial - 1),
                " more time(s)",
                exit=False,
            )
            info("Waiting for 2-10 seconds before retrying mount...")
            if not get_global_config().pretend:
                time.sleep(2 + 8 * random.random())  # wait 2-10 seconds, hopefully the server is less busy then.
    return False
