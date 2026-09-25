// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin || freebsd

package fmw

import "syscall"

// freeSpace is the space available to this user in bytes, or -1 when unknown.
func freeSpace(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	free := uint64(st.Bavail) * uint64(st.Bsize) //nolint:unconvert // The field types differ between systems.
	if free > 1<<62 {
		return 1 << 62
	}
	return int64(free)
}
