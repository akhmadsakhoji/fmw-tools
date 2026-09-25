// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package fmw

import (
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// freeSpace is the space available to this user in bytes, or -1 when unknown.
func freeSpace(dir string) int64 {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var avail, total, totalFree uint64
	r, _, _ := getDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return -1
	}
	if avail > 1<<62 {
		return 1 << 62
	}
	return int64(avail)
}
