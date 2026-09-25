// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test archives are built here the way the plugin builds them, so crafted
// (and hostile) content can be tested without the plugin.

const testIterations = MinIterations // Fast; the real default is 600,000.

type tEntry struct {
	name, link string
	typ        byte
	body       string
	mode       int64
}

// tarOf builds a TAR stream (a file part's content).
func tarOf(t *testing.T, entries ...tEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: typ, Mode: mode, ModTime: time.Unix(1700000000, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return b.Bytes()
}

type tPart struct {
	path, typ, table string
	content          []byte // Before compression.
	gzip             bool
	entries, raw     int64
}

type tArchive struct {
	parts    []tPart
	password string
	header   map[string]any // Extra or replacement fmw.json keys.
	manifest map[string]any // Extra or replacement manifest keys.
	mutate   func(name string, data []byte) []byte
	extra    map[string][]byte // Additional container entries.
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	z.Write(data)
	z.Close()
	return b.Bytes()
}

func encrypt(t *testing.T, plain []byte, password string) ([]byte, string) {
	t.Helper()
	salt := make([]byte, 8)
	rand.Read(salt)
	k, err := DeriveKeys(password, salt, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	pad := blockSize - len(plain)%blockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(k.AES)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, k.IV).CryptBlocks(out, padded)
	stored := append(append([]byte(Magic), salt...), out...)
	m := NewMAC(k)
	m.Write(stored)
	return stored, hex.EncodeToString(m.Sum(nil))
}

// build writes the archive and returns its path.
func (ta tArchive) build(t *testing.T) string {
	t.Helper()
	enc := ta.password != ""
	var records []map[string]any
	stored := map[string][]byte{}
	var order []string
	for _, p := range ta.parts {
		data := p.content
		compression := "none"
		if p.gzip {
			data = gz(t, data)
			compression = "gzip"
		}
		rec := map[string]any{"path": p.path, "type": p.typ, "compression": compression, "bytes_raw": p.raw}
		if p.typ == TypeDatabase {
			rec["table"], rec["chunk"], rec["rows"] = p.table, 1, 1
		} else {
			rec["entries"] = p.entries
		}
		if enc {
			rec["bytes_plain"] = len(data)
			var mac string
			data, mac = encrypt(t, data, ta.password)
			rec["hmac"] = mac
		}
		sum := sha256.Sum256(data)
		rec["sha256"], rec["bytes"] = hex.EncodeToString(sum[:]), len(data)
		records = append(records, rec)
		stored[p.path] = data
		order = append(order, p.path)
	}
	manifest := map[string]any{
		"format": "fmw", "version": 1, "created_at": "2026-09-24T11:00:00Z", "generator": "test",
		"site":    map[string]any{"home_url": "https://example.com", "site_url": "https://example.com", "content_dir": "wp-content", "table_prefix": "wp_"},
		"options": map[string]any{"exclude": []string{}, "encrypted": enc},
		"totals":  map[string]any{"files": 1},
		"parts":   records,
	}
	for k, v := range ta.manifest {
		manifest[k] = v
	}
	mjson, _ := json.Marshal(manifest)
	header := map[string]any{"format": "fmw", "version": 1, "created_at": "2026-09-24T11:00:00Z", "generator": "test", "encrypted": enc}
	mname := "manifest.json"
	if enc {
		var mac string
		mjson, mac = encrypt(t, mjson, ta.password)
		header["kdf"] = map[string]any{"algorithm": "pbkdf2-sha256", "iterations": testIterations}
		header["cipher"] = "aes-256-cbc"
		header["manifest_hmac"] = mac
		mname = "manifest.json.enc"
	}
	for k, v := range ta.header {
		header[k] = v
	}
	hjson, _ := json.Marshal(header)

	path := filepath.Join(t.TempDir(), "test.fmw")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	add := func(name string, data []byte) {
		if ta.mutate != nil {
			data = ta.mutate(name, data)
		}
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o644, Typeflag: tar.TypeReg, ModTime: time.Unix(1700000000, 0)})
		tw.Write(data)
	}
	add("fmw.json", hjson)
	for _, name := range order {
		add(name, stored[name])
	}
	for name, data := range ta.extra {
		add(name, data)
	}
	add(mname, mjson)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path
}

// filesPart is a gzip file part holding these entries.
func filesPart(t *testing.T, entries ...tEntry) tPart {
	var raw int64
	for _, e := range entries {
		if e.typ == 0 || e.typ == tar.TypeReg {
			raw += int64(len(e.body))
		}
	}
	return tPart{path: "files/part-0001.tar.gz", typ: TypeFiles, content: tarOf(t, entries...), gzip: true, entries: int64(len(entries)), raw: raw}
}

func sqlPart(n int, table, sql string) tPart {
	return tPart{path: fmt.Sprintf("database/%04d-%s.0001.sql.gz", n, table), typ: TypeDatabase, table: table, content: []byte(sql), gzip: true, raw: int64(len(sql))}
}

// encryptedNames renames parts the way the plugin does for encrypted backups.
func encryptedNames(parts []tPart) []tPart {
	out := append([]tPart(nil), parts...)
	for i, p := range out {
		if m := regexpDB.FindStringSubmatch(p.path); m != nil {
			out[i].path = "database/" + m[1] + "." + m[2] + ".sql.gz.enc"
		} else {
			out[i].path += ".enc"
		}
	}
	return out
}
