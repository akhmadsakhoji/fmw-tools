// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin || freebsd

package cli

import (
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func getTermios(fd uintptr) (*syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGet, uintptr(unsafe.Pointer(&t))); e != 0 {
		return nil, e
	}
	return &t, nil
}

func setTermios(fd uintptr, t *syscall.Termios) {
	syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSet, uintptr(unsafe.Pointer(t))) //nolint:errcheck // Best effort.
}

func isTerminal(f *os.File) bool {
	_, err := getTermios(f.Fd())
	return err == nil
}

// readPassword reads one line from the terminal without echoing it.
func readPassword(f *os.File) (string, error) {
	fd := f.Fd()
	old, err := getTermios(fd)
	if err != nil {
		return readLine(f)
	}
	quiet := *old
	quiet.Lflag &^= syscall.ECHO
	quiet.Lflag |= syscall.ICANON | syscall.ISIG
	quiet.Iflag |= syscall.ICRNL
	setTermios(fd, &quiet)

	// No signal may leave the terminal without echo: Ctrl+C, Ctrl+\ and a
	// hang-up end the program after restoring it; Ctrl+Z is ignored while
	// the prompt is open (a suspended program could not restore it).
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTSTP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sig:
				if s == syscall.SIGTSTP {
					continue
				}
				setTermios(fd, old)
				os.Stderr.WriteString("\n")
				os.Exit(130)
			case <-done:
				return
			}
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sig)
		setTermios(fd, old)
	}()
	return readLine(f)
}
