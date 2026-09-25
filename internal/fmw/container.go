// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one file inside a container.
type Entry struct {
	Name   string
	Offset int64 // Start of the data in the TAR file (0 in directory mode).
	Size   int64
}

// Container gives access to the entries of an .fmw archive: one TAR file,
// or a folder holding the same entries as plain files (format v1, section 1,
// "directory mode").
type Container struct {
	path    string
	dir     bool
	file    *os.File
	entries []Entry
	index   map[string]int
}

// OpenContainer reads the entry list. For a TAR file it walks the headers
// and seeks over the data, so a 100 GB archive costs one small read per entry.
func OpenContainer(path string) (*Container, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	c := &Container{path: path, index: map[string]int{}}
	if info.IsDir() {
		c.dir = true
		return c, c.scanDir()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	c.file = f
	if err := c.scanTar(); err != nil {
		f.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the archive file.
func (c *Container) Close() error {
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}

// Dir tells whether the archive is a folder (directory mode).
func (c *Container) Dir() bool { return c.dir }

// Entries lists the entries in archive order.
func (c *Container) Entries() []Entry { return c.entries }

// Lookup finds an entry by name.
func (c *Container) Lookup(name string) (Entry, bool) {
	i, ok := c.index[name]
	if !ok {
		return Entry{}, false
	}
	return c.entries[i], true
}

// Open returns the data of an entry.
func (c *Container) Open(e Entry) (io.ReadCloser, error) {
	if !c.dir {
		return io.NopCloser(io.NewSectionReader(c.file, e.Offset, e.Size)), nil
	}
	f, err := os.Open(filepath.Join(c.path, filepath.FromSlash(e.Name)))
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ReadSmall reads a whole entry of at most limit bytes (JSON files).
func (c *Container) ReadSmall(name string, limit int64) ([]byte, error) {
	e, ok := c.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s is missing: %w", name, ErrNotFMW)
	}
	if e.Size > limit {
		return nil, &FormatError{Msg: fmt.Sprintf("%s is unreasonably large (%d bytes)", name, e.Size)}
	}
	r, err := c.Open(e)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != e.Size {
		return nil, &FormatError{Msg: fmt.Sprintf("%s is truncated", name)}
	}
	return data, nil
}

func (c *Container) add(e Entry) error {
	if _, dup := c.index[e.Name]; dup {
		return &FormatError{Msg: fmt.Sprintf("entry %s appears twice in the archive", printable(e.Name))}
	}
	c.index[e.Name] = len(c.entries)
	c.entries = append(c.entries, e)
	return nil
}

func (c *Container) scanTar() error {
	tr := tar.NewReader(c.file)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if len(c.entries) == 0 {
				return fmt.Errorf("%w (not a TAR archive: %v)", ErrNotFMW, err)
			}
			return &FormatError{Msg: fmt.Sprintf("the archive is damaged or truncated after %s: %v", printable(c.entries[len(c.entries)-1].Name), err)}
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return &FormatError{Msg: fmt.Sprintf("unexpected entry type in the archive: %s", printable(h.Name))}
		}
		// archive/tar reads headers block by block without buffering ahead,
		// so the file position is now the start of this entry's data.
		offset, err := c.file.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if err := c.add(Entry{Name: h.Name, Offset: offset, Size: h.Size}); err != nil {
			return err
		}
	}
	if len(c.entries) == 0 {
		return fmt.Errorf("%w (empty archive)", ErrNotFMW)
	}
	return nil
}

// scanDir lists fmw.json, the manifest and every file in the part folders.
func (c *Container) scanDir() error {
	var names []string
	for _, top := range []string{"fmw.json", "manifest.json", "manifest.json.enc"} {
		if info, err := os.Lstat(filepath.Join(c.path, top)); err == nil && info.Mode().IsRegular() {
			names = append(names, top)
		}
	}
	for _, folder := range []string{"database", "files", "root-files"} {
		items, err := os.ReadDir(filepath.Join(c.path, folder))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.Type().IsRegular() {
				names = append(names, folder+"/"+item.Name())
			}
		}
	}
	// Archive order: fmw.json first, parts by name, manifest last.
	sort.SliceStable(names, func(i, j int) bool {
		return rank(names[i]) < rank(names[j]) || (rank(names[i]) == rank(names[j]) && names[i] < names[j])
	})
	for _, name := range names {
		info, err := os.Stat(filepath.Join(c.path, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		if err := c.add(Entry{Name: name, Size: info.Size()}); err != nil {
			return err
		}
	}
	if _, ok := c.index["fmw.json"]; !ok {
		return fmt.Errorf("%w (the folder has no fmw.json)", ErrNotFMW)
	}
	return nil
}

func rank(name string) int {
	switch {
	case name == "fmw.json":
		return 0
	case strings.HasPrefix(name, "manifest.json"):
		return 2
	}
	return 1
}
