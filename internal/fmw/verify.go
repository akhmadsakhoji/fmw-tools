// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Parts    int      `json:"parts"`
	Bytes    int64    `json:"bytes"`
	Deep     bool     `json:"deep"`
	Problems []string `json:"problems"`
}

// OK tells whether nothing was wrong.
func (r *VerifyReport) OK() bool { return len(r.Problems) == 0 }

// VerifyTotal is the number of bytes Verify reads (for progress).
func VerifyTotal(m *Manifest, deep bool) int64 {
	var total int64
	for _, p := range m.Parts {
		total += p.Bytes
	}
	if deep {
		total *= 2
	}
	return total
}

// Verify checks every part: presence, size, SHA-256 and, when encrypted, the
// HMAC. With deep it also decrypts and decompresses every part and walks its
// content: TAR headers and path safety of file parts, gzip checksums, and
// the sizes and entry counts recorded in the manifest. The error is only for
// problems that stop verification (password, unreadable manifest).
func (a *Archive) Verify(password string, deep bool, progress func(int64)) (*VerifyReport, error) {
	m, err := a.Manifest(password)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Parts: len(m.Parts), Deep: deep, Problems: []string{}}
	a.PrepareKeys(m.Parts)

	listed := map[string]bool{"fmw.json": true, a.ManifestName(): true}
	for _, p := range m.Parts {
		listed[p.Path] = true
	}
	for _, e := range a.container.Entries() {
		if !listed[e.Name] {
			rep.Problems = append(rep.Problems, fmt.Sprintf("unexpected entry %s", printable(e.Name)))
		}
	}

	for _, p := range a.inArchiveOrder(m.Parts) {
		if err := a.CheckPart(p, progress); err != nil {
			var pe *PartError
			if !errors.As(err, &pe) {
				return nil, err
			}
			rep.Problems = append(rep.Problems, err.Error())
			continue
		}
		rep.Bytes += p.Bytes
		if deep {
			if msg := a.deepCheck(p, progress); msg != "" {
				rep.Problems = append(rep.Problems, "part "+p.Path+" "+msg)
			}
		}
	}
	return rep, nil
}

// inArchiveOrder sorts parts by their position in the container, so a TAR file is read front to back.
func (a *Archive) inArchiveOrder(parts []Part) []Part {
	out := append([]Part(nil), parts...)
	pos := func(p Part) int64 {
		if e, ok := a.container.Lookup(p.Path); ok {
			return e.Offset
		}
		return -1
	}
	if a.container.Dir() {
		return out
	}
	sort.SliceStable(out, func(i, j int) bool { return pos(out[i]) < pos(out[j]) })
	return out
}

type counter struct {
	r        io.Reader
	n        int64
	progress func(int64)
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.progress != nil && n > 0 {
		c.progress(int64(n))
	}
	return n, err
}

// deepCheck unpacks one (already checksummed) part; returns "" when it is sound.
func (a *Archive) deepCheck(p Part, progress func(int64)) string {
	stored, err := a.OpenDecrypted(p, progress)
	if err != nil {
		return err.Error()
	}
	defer stored.Close()
	decrypted := &counter{r: stored}
	var plain io.Reader = decrypted
	if p.Compression == "gzip" {
		z, err := gzip.NewReader(plain)
		if err != nil {
			return fmt.Sprintf("is not valid gzip: %v", err)
		}
		defer z.Close()
		plain = z
	}

	var raw int64
	guard := &entryGuard{part: p}
	switch p.Type {
	case TypeDatabase:
		n, err := io.Copy(io.Discard, io.LimitReader(plain, p.BytesRaw+1)) // A gzip bomb stops here.
		if err != nil {
			return fmt.Sprintf("cannot be unpacked: %v", err)
		}
		raw = n
	default:
		tr := tar.NewReader(plain)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Sprintf("has a damaged TAR stream after %d entries: %v", guard.entries, err)
			}
			// Link targets are not judged here: format v1 stores links as they
			// were, and extract decides which ones it can create safely.
			if _, err := guard.check(h); err != nil {
				return strings.TrimPrefix(err.Error(), "part "+p.Path+" ")
			}
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return fmt.Sprintf("has a damaged entry %s: %v", printable(h.Name), err)
			}
		}
		raw = guard.raw
		if guard.entries != p.Entries {
			return fmt.Sprintf("has %d entries; the manifest says %d", guard.entries, p.Entries)
		}
	}
	// Anything after the TAR end blocks is padding; reading it also checks gzip CRCs and the SHA-256 again.
	if raw <= p.BytesRaw {
		if _, err := io.Copy(io.Discard, plain); err != nil {
			return fmt.Sprintf("has damaged data at its end: %v", err)
		}
	}
	if _, err := io.Copy(io.Discard, decrypted); err != nil {
		return strings.TrimPrefix(err.Error(), "part "+p.Path+" ")
	}
	if p.Encrypted() && p.BytesPlain > 0 && decrypted.n != p.BytesPlain {
		return fmt.Sprintf("decrypts to %d bytes; the manifest says %d", decrypted.n, p.BytesPlain)
	}
	if raw != p.BytesRaw {
		if raw > p.BytesRaw {
			return fmt.Sprintf("holds more data than the %d bytes the manifest records", p.BytesRaw)
		}
		return fmt.Sprintf("holds %d bytes of data; the manifest says %d", raw, p.BytesRaw)
	}
	return ""
}
