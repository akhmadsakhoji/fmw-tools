// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !darwin && !freebsd && !windows

package fmw

// freeSpace is unknown on this system.
func freeSpace(string) int64 { return -1 }
