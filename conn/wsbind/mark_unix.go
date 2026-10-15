//go:build linux || openbsd || freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

// controlMark sets mark on a socket before it connects or listens. A zero
// mark leaves the socket alone.
func controlMark(c syscall.RawConn, mark uint32) error {
	if mark == 0 || fwmarkIoctl == 0 {
		return nil
	}
	var operr error
	err := c.Control(func(fd uintptr) {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	})
	if err != nil {
		return err
	}
	return operr
}

// setMark sets mark on an existing listener or connection.
func setMark(v any, mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	sc, ok := v.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var operr error
	err = rc.Control(func(fd uintptr) {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
	})
	if err != nil {
		return err
	}
	return operr
}
