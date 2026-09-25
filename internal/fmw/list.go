// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"
)

// FileInfo is one entry inside a file part.
type FileInfo struct {
	Part    string      `json:"part"`
	Path    string      `json:"path"` // Relative to wp-content (or the WordPress root for root-files).
	Type    string      `json:"type"` // file, dir, symlink or other.
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"mode"`
	ModTime time.Time   `json:"mtime"`
	Link    string      `json:"link,omitempty"`
}

// ListFiles calls fn for every entry in the file parts, optionally only
// under some paths. Each part is checked before its content is read.
func (a *Archive) ListFiles(password string, paths []string, progress func(int64), fn func(FileInfo)) error {
	m, err := a.Manifest(password)
	if err != nil {
		return err
	}
	var only []string
	for _, p := range paths {
		rel, err := SafeRelative(p)
		if err != nil {
			return err
		}
		if rel != "" {
			only = append(only, rel)
		}
	}
	var parts []Part
	for _, p := range m.Parts {
		if p.Type != TypeDatabase {
			parts = append(parts, p)
		}
	}
	parts = a.inArchiveOrder(parts)
	a.PrepareKeys(parts)
	for _, p := range parts {
		if err := a.CheckPart(p, progress); err != nil {
			return err
		}
		r, err := a.OpenPlain(p, progress)
		if err != nil {
			return err
		}
		guard := &entryGuard{part: p}
		tr := tar.NewReader(r)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				r.Close()
				return &PartError{Part: p.Path, Msg: fmt.Sprintf("has a damaged TAR stream: %v", err)}
			}
			rel, err := guard.check(h)
			if err != nil {
				r.Close()
				return err
			}
			if rel == "" || (len(only) > 0 && p.Type == TypeFiles && !wanted(rel, only)) {
				continue
			}
			fn(FileInfo{
				Part:    p.Path,
				Path:    rel,
				Type:    typeName(h.Typeflag),
				Size:    h.Size,
				Mode:    fs.FileMode(h.Mode).Perm(),
				ModTime: h.ModTime,
				Link:    h.Linkname,
			})
		}
		err = drain(r) // The part is checked against its SHA-256 again at its end.
		r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func typeName(t byte) string {
	switch t {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "dir"
	case tar.TypeSymlink:
		return "symlink"
	}
	return "other"
}
