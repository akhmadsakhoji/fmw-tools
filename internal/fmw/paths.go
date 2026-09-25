// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"fmt"
	"regexp"
	"strings"
)

var driveLetter = regexp.MustCompile(`^[A-Za-z]:`)

// SafeRelative checks a path from inside a part (format v1, section 2) and
// returns it cleaned: relative, "/"-separated, without "." or empty
// segments. Absolute paths, drive letters, backslashes, NUL bytes and ".."
// segments are refused.
func SafeRelative(name string) (string, error) {
	if strings.ContainsAny(name, "\x00\\") {
		return "", fmt.Errorf("unsafe characters in archive path %q", printable(name))
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute archive path %q", printable(name))
	}
	if driveLetter.MatchString(name) {
		return "", fmt.Errorf("drive letter in archive path %q", printable(name))
	}
	var out []string
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("parent directory reference in archive path %q", printable(name))
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/"), nil
}

// MaxLinkTarget is the longest link target extract accepts (PATH_MAX on Linux).
const MaxLinkTarget = 4096

// SymlinkTarget checks a link target and returns the path it points to,
// relative to the extraction root. The target must be relative, and ".."
// may only come first ("../../uploads/x" is fine, "a/../x" is not): a ".."
// after a folder name would be resolved by the file system through that
// folder, which may itself be a link (on case-insensitive file systems
// even under another spelling). With ".." only at the start, climbing
// happens from the link's own folder, which extract creates as a real folder.
func SymlinkTarget(link, target string) (string, error) {
	if target == "" || len(target) > MaxLinkTarget || strings.ContainsAny(target, "\x00\\") {
		return "", fmt.Errorf("invalid symlink target for %q", printable(link))
	}
	if strings.HasPrefix(target, "/") || driveLetter.MatchString(target) {
		return "", fmt.Errorf("absolute symlink target for %q", printable(link))
	}
	stack := strings.Split(link, "/")
	stack = stack[:len(stack)-1] // The link's own name.
	descending := false
	for _, seg := range strings.Split(target, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if descending {
				return "", fmt.Errorf("symlink %q has \"..\" after a folder name in its target", printable(link))
			}
			if len(stack) == 0 {
				return "", fmt.Errorf("symlink %q points outside the extraction folder", printable(link))
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			// Windows drops trailing dots and spaces: ".. " would climb there.
			return "", fmt.Errorf("symlink %q has a target segment ending in a dot or space", printable(link))
		}
		descending = true
		stack = append(stack, seg)
	}
	return strings.Join(stack, "/"), nil
}

var windowsReserved = regexp.MustCompile(`(?i)^(con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$`)

// WindowsProblem says why a path cannot be written on Windows ("" when it can).
// A colon would otherwise write an NTFS alternate data stream.
func WindowsProblem(rel string) string {
	for _, seg := range strings.Split(rel, "/") {
		if strings.ContainsAny(seg, `<>:"|?*`) {
			return "has characters Windows does not allow in file names"
		}
		for _, r := range seg {
			if r < 32 {
				return "has control characters"
			}
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return "ends with a dot or space, which Windows drops"
		}
		if windowsReserved.MatchString(seg) {
			return "uses a name reserved by Windows"
		}
	}
	return ""
}
