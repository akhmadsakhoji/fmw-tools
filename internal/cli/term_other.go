// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !darwin && !freebsd && !windows

package cli

import "os"

func isTerminal(*os.File) bool { return false }

// readPassword cannot hide the input on this system.
func readPassword(f *os.File) (string, error) { return readLine(f) }
