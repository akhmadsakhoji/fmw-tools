// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

const enableEchoInput = 0x0004

var setConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func isTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// readPassword reads one line from the console without echoing it.
func readPassword(f *os.File) (string, error) {
	h := syscall.Handle(f.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		return readLine(f)
	}
	setConsoleMode.Call(uintptr(h), uintptr(mode&^enableEchoInput)) //nolint:errcheck // Best effort.
	// Ctrl+C must not leave the console without echo.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			setConsoleMode.Call(uintptr(h), uintptr(mode)) //nolint:errcheck // Best effort.
			os.Stderr.WriteString("\r\n")
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sig)
		setConsoleMode.Call(uintptr(h), uintptr(mode)) //nolint:errcheck // Best effort.
	}()
	return readLine(f)
}
