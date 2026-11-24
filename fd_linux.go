// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import "syscall"

// socketpair returns a new AF_LOCAL SOCK_STREAM socketpair whose ends
// are both close-on-exec from birth, so spawned processes do not
// inherit them. Linux creates the pair atomically with SOCK_CLOEXEC.
func socketpair() ([2]int, error) {
	return syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
}

// Install the received descriptor close-on-exec in the kernel.
const recvFlags = syscall.MSG_CMSG_CLOEXEC

// closeOnExec marks fd close-on-exec. It is a no-op on Linux, where
// recvFlags already made received fds close-on-exec.
func closeOnExec(fd int) {}
