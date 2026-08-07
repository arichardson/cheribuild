#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
# -
# Copyright (c) 2026 Alex Richardson
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
# Linux-guest-specific boot/login/mount behaviour.
#
# The Linux images booted here (see pycheribuild/projects/cross/busybox.py,
# write_busybox_init()) have no bootloader menu, no login/getty, and no sshd:
# the kernel boots directly via -kernel/-initrd into a busybox /init script
# that drops straight to a bare `/bin/sh` (busybox ash) prompt in an infinite
# respawn loop, with networking already configured by the time the shell
# appears. There is also no interactive kernel debugger to fall back to on
# panic (unlike FreeBSD's `db>`).
import datetime
import typing

from ._common import (
    INITIAL_PROMPT_SH,
    CommandFailedError,
    GuestSpawnMixin,
    PatternListType,
    QemuGuestInstance,
    _set_pexpect_sh_prompt,
    checked_run_guest_command,
    failure,
    success,
)

# Plain string, not a compiled regex: PANIC_REGEXES entries must work with both expect() (regex)
# and expect_exact() (literal match, used by _set_pexpect_sh_prompt) -- pexpect's expect_exact()
# rejects compiled re.Pattern objects.
LINUX_PANIC = "Kernel panic - not syncing"


class QemuLinuxInstance(QemuGuestInstance):
    PANIC_REGEXES: "typing.ClassVar[PatternListType]" = [LINUX_PANIC]

    def handle_kernel_panic(self):
        # Unlike FreeBSD, there is no interactive kernel debugger to fall back to here.
        failure("GOT LINUX KERNEL PANIC: ", self.match, exit=False)


def boot_and_login_linux(child: GuestSpawnMixin, *, starttime) -> None:
    try:
        child.expect([INITIAL_PROMPT_SH], timeout=20 * 60, timeout_msg="timeout waiting for busybox shell prompt")
        success("===> got busybox ash prompt")
        _set_pexpect_sh_prompt(child)
        success("===> booted Linux (userspace startup time: ", datetime.datetime.now() - starttime, ")")
    except KeyboardInterrupt:
        failure("Keyboard interrupt during boot", exit=True)


def mount_via_9p_linux(d, qemu: QemuGuestInstance, share_name: str) -> bool:
    try:
        ro_flag = ",ro" if d.readonly else ""
        checked_run_guest_command(
            qemu, f"mount -t 9p -o trans=virtio,version=9p2000.L{ro_flag} {share_name} '{d.in_target}'"
        )
        d.mounted = True
        return True
    except CommandFailedError:
        d.mounted = False
        return False
