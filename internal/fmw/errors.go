// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"errors"
	"regexp"
)

var (
	// ErrNotFMW means the file is not an FMW archive at all.
	ErrNotFMW = errors.New("not an FMW archive")
	// ErrPasswordRequired means the archive is encrypted and no password was given.
	ErrPasswordRequired = errors.New("this backup is encrypted; a password is needed")
	// ErrWrongPassword means the manifest HMAC did not match: wrong password or a damaged manifest.
	ErrWrongPassword = errors.New("wrong password, or the backup's manifest is damaged")
)

// FormatError describes an archive that breaks format v1.
type FormatError struct{ Msg string }

func (e *FormatError) Error() string { return e.Msg }

// UnsupportedError describes an archive written for a newer format or with
// settings this version cannot read; updating FMW Tools may help.
type UnsupportedError struct{ Msg string }

func (e *UnsupportedError) Error() string { return e.Msg }

var unprintable = regexp.MustCompile(`[^\x20-\x7E]`)

// printable makes a name from an archive safe to show in a terminal.
func printable(s string) string {
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return unprintable.ReplaceAllString(s, "?")
}
