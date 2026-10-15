//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 christarcher. All Rights Reserved.
 */

package wsbind

import "syscall"

func controlMark(c syscall.RawConn, mark uint32) error { return nil }

func setMark(v any, mark uint32) error { return nil }
