#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Alex Richardson
#
# This work was supported by Innovate UK project 105694, "Digital Security by
# Design (DSbD) Technology Platform Prototype".
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Boot/smoke test for the Linux guest images (busybox-based, no kyua/
# cheribsdtest equivalent yet). Verifies the kernel boots without panicking,
# the busybox shell comes up, a couple of basic commands work, and the
# 9p-mounted test-results directory is reachable and writable.
import argparse
import os
from pathlib import Path

from run_tests_common import boot_automation, pexpect, run_tests_main

from pycheribuild.utils import get_global_config


def run_linux_test(qemu: "boot_automation.QemuGuestInstance", args: argparse.Namespace) -> bool:
    boot_automation.success("Booted Linux successfully")
    tests_successful = True
    try:
        qemu.checked_run("id")
        qemu.checked_run("uname -a")
        qemu.run(
            "dmesg > /tmp/dmesg.log; grep -Ei 'Call Trace|Oops|BUG:' /tmp/dmesg.log && "
            "echo DMESG_WARNINGS_FOUND || echo DMESG_CLEAN"
        )
        for shared_dir in qemu.shared_dirs:
            if shared_dir.in_target == "/test-results" and not shared_dir.readonly:
                qemu.checked_run(
                    "touch /test-results/.smoke-test-write-check && rm -f /test-results/.smoke-test-write-check"
                )
    except boot_automation.CommandFailedError as e:
        boot_automation.failure("Smoke-test command failed: ", e, exit=False)
        tests_successful = False

    # Extension point for a future LTP (Linux Test Project) follow-up:
    # if args.run_ltp_tests:
    #     tests_successful = run_ltp_tests(qemu, args) and tests_successful

    if args.interact or args.skip_poweroff:
        boot_automation.info("Skipping poweroff step since --interact/--skip-poweroff was passed.")
        return tests_successful

    qemu.sendline("poweroff -f")
    i = qemu.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=120)
    if i == 0:
        boot_automation.failure("Timeout waiting for QEMU to exit after poweroff", exit=False)
        return False
    return tests_successful


def linux_setup_args(args: argparse.Namespace):
    test_output_dir = Path(os.path.expandvars(os.path.expanduser(args.test_output_dir))).absolute()
    if not get_global_config().pretend:
        test_output_dir.mkdir(parents=True, exist_ok=True)
    args.test_output_dir = str(test_output_dir)
    args.shared_mount_directories.append(
        boot_automation.SharedMount(test_output_dir, readonly=False, in_target="/test-results"),
    )


def add_args(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--skip-poweroff",
        action="store_true",
        help="Don't run poweroff after tests (implicit with --interact).",
    )
    default_test_output = str(Path(".").resolve() / "linux-test-results")
    parser.add_argument(
        "--test-output-dir",
        default=default_test_output,
        help="Directory for the test outputs (mounted via 9pfs as /test-results)",
    )
    # Reserved for a future LTP (Linux Test Project) follow-up, not implemented yet:
    # parser.add_argument("--run-ltp-tests", action="store_true", default=False)


if __name__ == "__main__":
    # busybox's /init has no sshd, so we always rely on 9pfs/SMB sharing instead of SSH.
    run_tests_main(
        test_function=run_linux_test,
        argparse_setup_callback=add_args,
        argparse_adjust_args_callback=linux_setup_args,
        should_mount_builddir=False,
        need_ssh=False,
    )
