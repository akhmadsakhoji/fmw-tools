// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package cli

import "syscall"

const (
	ioctlGet = syscall.TCGETS
	ioctlSet = syscall.TCSETS
)
