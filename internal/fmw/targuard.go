// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"fmt"
	"strings"
)

// MaxPath is the longest path inside a part that is accepted (PATH_MAX on Linux).
const MaxPath = 4096

// entryGuard applies the rules every reader of a file part shares (verify
// --deep, list, extract): safe paths, no sparse files (Go's TAR reader would
// expand their holes: a few bytes could claim exabytes), sane link targets,
// and never more data than the manifest records for the part.
type entryGuard struct {
	part    Part
	raw     int64
	entries int64
}

// check validates one header and returns its cleaned path ("" for the root itself).
func (g *entryGuard) check(h *tar.Header) (string, error) {
	g.entries++
	if isSparse(h) {
		return "", &PartError{Part: g.part.Path, Msg: fmt.Sprintf("contains the sparse file %s, which format v1 does not use", printable(h.Name))}
	}
	rel, err := SafeRelative(h.Name)
	if err != nil {
		return "", &PartError{Part: g.part.Path, Msg: "contains an " + err.Error()}
	}
	if len(rel) > MaxPath { // No file system stores it, and deep paths would cost memory.
		return "", &PartError{Part: g.part.Path, Msg: fmt.Sprintf("has an unreasonably long path (%d bytes)", len(rel))}
	}
	if len(h.Linkname) > MaxLinkTarget {
		return "", &PartError{Part: g.part.Path, Msg: fmt.Sprintf("has an unreasonably long link target for %s", printable(rel))}
	}
	if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
		if h.Size < 0 {
			return "", &PartError{Part: g.part.Path, Msg: fmt.Sprintf("has a negative size for %s", printable(rel))}
		}
		if h.Size > g.part.BytesRaw-g.raw { // Compared before adding: the sum cannot overflow.
			return "", &PartError{Part: g.part.Path, Msg: fmt.Sprintf("holds more data than the %d bytes the manifest records", g.part.BytesRaw)}
		}
		g.raw += h.Size
	}
	return rel, nil
}

func isSparse(h *tar.Header) bool {
	if h.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}
