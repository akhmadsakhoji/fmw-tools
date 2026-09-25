// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestFormatRules(t *testing.T) {
	good := []tPart{sqlPart(1, "wp_options", "SET NAMES utf8mb4;")}
	cases := []struct {
		name string
		arch tArchive
		want any // error type or sentinel
		msg  string
	}{
		{"newer version", tArchive{parts: good, header: map[string]any{"version": 2}}, &UnsupportedError{}, "newer"},
		{"not fmw", tArchive{parts: good, header: map[string]any{"format": "zip"}}, ErrNotFMW, "unknown format"},
		{"unknown compression", tArchive{parts: good, manifest: map[string]any{"parts": []map[string]any{{"path": "database/0001-x.0001.sql.zst", "type": "database", "compression": "zstd", "bytes": 1, "bytes_raw": 1, "sha256": strings.Repeat("a", 64)}}}}, &UnsupportedError{}, "compression"},
		{"unknown type", tArchive{parts: good, manifest: map[string]any{"parts": []map[string]any{{"path": "database/x", "type": "media", "compression": "gzip", "bytes": 1, "sha256": strings.Repeat("a", 64)}}}}, &UnsupportedError{}, "part type"},
		{"unsafe part name", tArchive{parts: good, manifest: map[string]any{"parts": []map[string]any{{"path": "files/../../x", "type": "files", "compression": "gzip", "bytes": 1, "sha256": strings.Repeat("a", 64)}}}}, &FormatError{}, "unsafe part name"},
		{"incomplete encrypted", tArchive{parts: encryptedNames(good), password: "pw", header: map[string]any{"manifest_hmac": strings.Repeat("0", 64)}}, &FormatError{}, "incomplete"},
		{"weak kdf", tArchive{parts: encryptedNames(good), password: "pw", header: map[string]any{"kdf": map[string]any{"algorithm": "pbkdf2-sha256", "iterations": 1}}}, &FormatError{}, "key derivation"},
		{"other cipher", tArchive{parts: encryptedNames(good), password: "pw", header: map[string]any{"cipher": "chacha20"}}, &UnsupportedError{}, "encryption"},
		{"plain part in encrypted backup", tArchive{parts: good, password: "pw"}, &FormatError{}, "encryption setting"},
	}
	for _, c := range cases {
		path := c.arch.build(t)
		a, err := Open(path)
		if err == nil {
			_, err = a.Manifest(c.arch.password)
			a.Close()
		}
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: got %v", c.name, err)
			continue
		}
		switch w := c.want.(type) {
		case error:
			var ue *UnsupportedError
			var fe *FormatError
			switch w.(type) {
			case *UnsupportedError:
				if !errors.As(err, &ue) {
					t.Errorf("%s: %T is not UnsupportedError", c.name, err)
				}
			case *FormatError:
				if !errors.As(err, &fe) {
					t.Errorf("%s: %T is not FormatError", c.name, err)
				}
			default:
				if !errors.Is(err, w) {
					t.Errorf("%s: %v is not %v", c.name, err, w)
				}
			}
		}
	}
}

func TestUnknownKeysAreIgnored(t *testing.T) {
	path := tArchive{
		parts:    []tPart{sqlPart(1, "wp_options", "SET NAMES utf8mb4;")},
		header:   map[string]any{"future": map[string]any{"x": 1}},
		manifest: map[string]any{"future_key": []int{1, 2}},
	}.build(t)
	rep, err := openT(t, path).Verify("", true, nil)
	if err != nil || !rep.OK() {
		t.Fatal(err, rep)
	}
}

func TestVerifyReportsMissingUnexpectedAndDeepProblems(t *testing.T) {
	part := filesPart(t, tEntry{name: "a.txt", body: "abc"})
	part.entries = 5 // The manifest claims more entries than the part holds.
	path := tArchive{
		parts: []tPart{part, sqlPart(1, "wp_options", "SET NAMES utf8mb4;")},
		extra: map[string][]byte{"files/intruder.tar": []byte("x")},
		mutate: func(name string, data []byte) []byte {
			if strings.HasPrefix(name, "database/") {
				return nil // Replaced by an empty entry: size mismatch.
			}
			return data
		},
	}.build(t)
	a := openT(t, path)
	rep, err := a.Verify("", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Problems, "\n")
	if len(rep.Problems) != 2 || !strings.Contains(joined, "unexpected entry files/intruder.tar") || !strings.Contains(joined, "is 0 bytes") {
		t.Fatalf("problems: %v", rep.Problems)
	}
	rep, _ = a.Verify("", true, nil)
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "has 1 entries; the manifest says 5") {
		t.Fatalf("deep problems: %v", rep.Problems)
	}
}

func TestDecryptReaderStreamsAndChecksPadding(t *testing.T) {
	plain := bytes.Repeat([]byte("0123456789abcdef-"), 5000)
	for _, n := range []int{0, 1, 15, 16, 17, len(plain)} {
		stored, _ := encrypt(t, plain[:n], "pw")
		salt, _ := SaltOf(stored[:HeaderLen])
		k, _ := DeriveKeys("pw", salt, testIterations)
		d, _ := NewDecryptReader(iotest.OneByteReader(bytes.NewReader(stored[HeaderLen:])), k)
		got, err := io.ReadAll(d)
		if err != nil || !bytes.Equal(got, plain[:n]) {
			t.Fatalf("n=%d: %v", n, err)
		}
		// Truncated ciphertext is refused.
		d, _ = NewDecryptReader(bytes.NewReader(stored[HeaderLen:len(stored)-1]), k)
		if _, err := io.ReadAll(d); !errors.Is(err, ErrBadPadding) {
			t.Fatalf("n=%d truncated: %v", n, err)
		}
	}
}

// OpenSSL's "enc -pbkdf2" is the reference for the first 48 derived bytes (format v1, section 7).
func TestOpenSSLCompatibility(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "in.enc")
	stored, _ := encrypt(t, []byte("hello from fmw-tools\n"), "pass word")
	os.WriteFile(in, stored, 0o600)
	out, err := exec.Command(openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-md", "sha256", "-pass", "pass:pass word", "-in", in).Output()
	if err != nil || string(out) != "hello from fmw-tools\n" {
		t.Fatalf("openssl could not decrypt our file: %v %q", err, out)
	}
	enc := filepath.Join(dir, "by-openssl.enc")
	cmd := exec.Command(openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-md", "sha256", "-salt", "-pass", "pass:pass word", "-out", enc)
	cmd.Stdin = strings.NewReader("hello from openssl\n")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(enc)
	salt, err := SaltOf(data[:HeaderLen])
	if err != nil {
		t.Fatal(err)
	}
	k, _ := DeriveKeys("pass word", salt, 10000)
	d, _ := NewDecryptReader(bytes.NewReader(data[HeaderLen:]), k)
	got, err := io.ReadAll(d)
	if err != nil || string(got) != "hello from openssl\n" {
		t.Fatalf("we could not decrypt openssl's file: %v %q", err, got)
	}
}

func TestDecryptKeepsUnknownKeysAndOrder(t *testing.T) {
	parts := encryptedNames([]tPart{sqlPart(1, "wp_options", "SET NAMES utf8mb4;"), filesPart(t, tEntry{name: "a.txt", body: "abc"})})
	path := tArchive{parts: parts, password: "pw", manifest: map[string]any{"zz_future": "kept"}}.build(t)
	a := openT(t, path)
	out := filepath.Join(t.TempDir(), "plain.fmw")
	if err := a.Decrypt("pw", out, nil); err != nil {
		t.Fatal(err)
	}
	b := openT(t, out)
	if b.Encrypted() {
		t.Fatal("output is still marked encrypted")
	}
	rep, err := b.Verify("", true, nil)
	if err != nil || !rep.OK() {
		t.Fatal(err, rep)
	}
	m, _ := b.Manifest("")
	if m.Parts[0].Path != "database/0001-wp_options.0001.sql.gz" || m.Parts[1].Path != "files/part-0001.tar.gz" || m.Parts[0].HMAC != "" || m.Options.Encrypted {
		t.Fatalf("parts: %+v", m.Parts)
	}
	raw := string(m.RawManifest())
	if !strings.Contains(raw, `"zz_future": "kept"`) || strings.Index(raw, `"format"`) > strings.Index(raw, `"parts"`) {
		t.Fatalf("manifest lost keys or order:\n%s", raw)
	}
	var header map[string]any
	json.Unmarshal(b.RawHeader(), &header)
	if _, ok := header["kdf"]; ok || header["decrypted_by"] == nil {
		t.Fatalf("header: %v", header)
	}
	// An existing file is replaced only through the .partial rename; nothing is left behind.
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Fatal(".partial left behind")
	}
}

func TestDirectoryModeArchive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backup")
	f, _ := os.Open(plainFixture)
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, filepath.FromSlash(h.Name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		data, _ := io.ReadAll(tr)
		os.WriteFile(p, data, 0o644)
	}
	a := openT(t, dir)
	rep, err := a.Verify("", true, nil)
	if err != nil || !rep.OK() || rep.Parts != 17 {
		t.Fatal(err, rep)
	}
}

func TestPathRules(t *testing.T) {
	for in, want := range map[string]string{"a/b": "a/b", "./a//b/": "a/b", "": "", ".": ""} {
		if got, err := SafeRelative(in); err != nil || got != want {
			t.Errorf("SafeRelative(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"../a", "a/../../b", "/a", `a\b`, "C:x", "a\x00"} {
		if _, err := SafeRelative(bad); err == nil {
			t.Errorf("SafeRelative(%q) accepted", bad)
		}
	}
	if got, err := SymlinkTarget("a/b/link", "../c"); err != nil || got != "a/c" {
		t.Errorf("SymlinkTarget: %q %v", got, err)
	}
	for _, bad := range [][2]string{{"link", ".."}, {"a/link", "../../x"}, {"link", "/etc"}, {"link", ""}} {
		if _, err := SymlinkTarget(bad[0], bad[1]); err == nil {
			t.Errorf("SymlinkTarget(%q, %q) accepted", bad[0], bad[1])
		}
	}
	for name, bad := range map[string]bool{"uploads/a.jpg": false, "a:b": true, "CON": true, "con.txt": true, "x/aux": true, "dot.": true, "q?": true, "console.log": false} {
		if (WindowsProblem(name) != "") != bad {
			t.Errorf("WindowsProblem(%q) = %q", name, WindowsProblem(name))
		}
	}
	if PlainName(Part{Path: "database/0003.0002.sql.gz.enc", Table: "wp_posts"}) != "database/0003-wp_posts.0002.sql.gz" ||
		PlainName(Part{Path: "database/0004.0001.sql.gz.enc", Table: "wp_weird table!"}) != "database/0004-wp_weird_table_.0001.sql.gz" ||
		PlainName(Part{Path: "files/part-0001.tar.enc"}) != "files/part-0001.tar" {
		t.Error("PlainName")
	}
}
