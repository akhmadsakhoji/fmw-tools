// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Link targets may only climb at the start: "B/../x" would be resolved by
// the file system through B, which may be a link spelled differently on a
// case-insensitive file system.
func TestLinkTargetsOnlyClimbFirst(t *testing.T) {
	ok := map[[2]string]string{
		{"a/l", "../x"}:                "x",
		{"a/b/l", "../../x/y"}:         "x/y",
		{"a/l", "./x/./y"}:             "a/x/y",
		{"uploads/ok", "../index.php"}: "index.php",
	}
	for in, want := range ok {
		if got, err := SymlinkTarget(in[0], in[1]); err != nil || got != want {
			t.Errorf("SymlinkTarget(%q, %q) = %q, %v", in[0], in[1], got, err)
		}
	}
	for _, bad := range [][2]string{{"d1/d2/l", "B/../secret"}, {"l", "x/../y"}, {"d1/d2/b", "../../.."}, {"l", strings.Repeat("a", MaxLinkTarget+1)}} {
		if _, err := SymlinkTarget(bad[0], bad[1]); err == nil {
			t.Errorf("SymlinkTarget(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

func TestCaseVariantLinkChainIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}
	path := tArchive{parts: []tPart{filesPart(t,
		tEntry{name: "d1/d2/l", typ: tar.TypeSymlink, link: "B/../secret"},
		tEntry{name: "d1/d2/b", typ: tar.TypeSymlink, link: "../../.."},
	)}}.build(t)
	dest, outside, st, warns, err := extractT(t, path, "", ExtractOptions{Symlinks: true})
	// "b" sits in wp-content/d1/d2, so ../../.. is the extraction folder itself: allowed.
	if err != nil || st.Symlinks != 1 || len(warns) != 1 {
		t.Fatalf("%v %+v %v", err, st, warns)
	}
	if _, err := os.Lstat(filepath.Join(dest, "wp-content/d1/d2/l")); err == nil {
		t.Fatal("link created")
	}
	assertEmpty(t, outside)
}

func TestSparseEntriesAreRefused(t *testing.T) {
	g := &entryGuard{part: Part{Path: "files/part-0001.tar", BytesRaw: 1 << 40}}
	for _, h := range []*tar.Header{
		{Name: "big", Typeflag: tar.TypeReg, Size: 1, PAXRecords: map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}},
		{Name: "old", Typeflag: tar.TypeGNUSparse, Size: 1},
	} {
		if _, err := g.check(h); err == nil || !strings.Contains(err.Error(), "sparse") {
			t.Errorf("%s: %v", h.Name, err)
		}
	}
}

func TestPartsCannotHoldMoreThanTheManifestSays(t *testing.T) {
	part := filesPart(t, tEntry{name: "a.txt", body: strings.Repeat("x", 1000)})
	part.raw = 10
	path := tArchive{parts: []tPart{part}}.build(t)
	if _, _, _, _, err := extractT(t, path, "", ExtractOptions{Files: true}); err == nil || !strings.Contains(err.Error(), "more data than") {
		t.Fatalf("extract: %v", err)
	}
	rep, err := openT(t, path).Verify("", true, nil)
	if err != nil || len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], "more data than") {
		t.Fatalf("verify: %v %v", err, rep)
	}
	sql := sqlPart(1, "wp_options", strings.Repeat("INSERT INTO x VALUES (1);\n", 100))
	sql.raw = 20
	path = tArchive{parts: []tPart{sql}}.build(t)
	if _, _, _, _, err := extractT(t, path, "", ExtractOptions{Database: true, PlainSQL: true}); err == nil || !strings.Contains(err.Error(), "more data than") {
		t.Fatalf("sql: %v", err)
	}
}

func TestExtractChecksDiskSpace(t *testing.T) {
	if freeSpace(t.TempDir()) < 0 {
		t.Skip("free space unknown on this system")
	}
	part := filesPart(t, tEntry{name: "a.txt", body: "small"})
	part.raw = 1 << 60 // The manifest claims an exabyte.
	path := tArchive{parts: []tPart{part}}.build(t)
	if _, _, _, _, err := extractT(t, path, "", ExtractOptions{Files: true}); err == nil || !strings.Contains(err.Error(), "not enough disk space") {
		t.Fatalf("expected a space error, got %v", err)
	}
	if _, _, _, _, err := extractT(t, path, "", ExtractOptions{Files: true, SkipSpaceCheck: true}); err != nil {
		t.Fatalf("with the check skipped: %v", err)
	}
}

func TestRootFilesAllowlist(t *testing.T) {
	entries := []tEntry{
		{name: ".htaccess", body: "RewriteEngine On"},
		{name: "google1234abcd.html", body: "google-site-verification"},
		{name: "wp-config.php", body: "<?php define('DB_PASSWORD', 'x');"},
		{name: "evil.php", body: "<?php"},
		{name: "sub/robots.txt", body: "x"},
	}
	root := filesPart(t, entries...)
	root.path, root.typ = "root-files/root.tar.gz", TypeRootFiles
	path := tArchive{parts: []tPart{root}}.build(t)
	dest, _, st, warns, err := extractT(t, path, "", ExtractOptions{Root: true})
	if err != nil || st.Files != 2 || st.Skipped != 3 || len(warns) != 3 {
		t.Fatalf("%v %+v %v", err, st, warns)
	}
	for _, name := range []string{"wp-config.php", "evil.php", "sub"} {
		if _, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Fatalf("%s was written to the WordPress root", name)
		}
	}
}

func TestModesAreMaskedLikeAUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := tArchive{parts: []tPart{filesPart(t,
		tEntry{name: "open", typ: tar.TypeDir, mode: 0o777},
		tEntry{name: "open/w.php", body: "<?php", mode: 0o666},
	)}}.build(t)
	dest, _, _, _, err := extractT(t, path, "", ExtractOptions{Files: true})
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]os.FileMode{"wp-content/open": 0o755, "wp-content/open/w.php": 0o644} {
		info, _ := os.Stat(filepath.Join(dest, rel))
		if info.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", rel, info.Mode().Perm(), want)
		}
	}
}

func TestDecryptRefusesToOverwriteTheBackup(t *testing.T) {
	path := tArchive{parts: encryptedNames([]tPart{sqlPart(1, "wp_options", "SET NAMES utf8mb4;")}), password: "pw"}.build(t)
	a := openT(t, path)
	if err := a.Decrypt("pw", path, nil); err == nil || !strings.Contains(err.Error(), "cannot replace the backup") {
		t.Fatalf("same file: %v", err)
	}
	if b, _ := os.ReadFile(path); len(b) == 0 {
		t.Fatal("the backup was damaged")
	}
	dir := filepath.Join(t.TempDir(), "backup-20260924-224438-3c6def.fmw")
	os.MkdirAll(dir, 0o755)
	m := &Manifest{Site: Site{HomeURL: "https://Example.com:8443/"}}
	if got := DecryptedName(dir+string(filepath.Separator), m); got != filepath.Join(filepath.Dir(dir), "example.com-20260924-224438-3c6def.fmw") {
		t.Fatalf("DecryptedName: %s", got)
	}
	if !sameOrInside(dir, filepath.Join(dir, "x.fmw")) || sameOrInside(dir, filepath.Join(filepath.Dir(dir), "x.fmw")) {
		t.Fatal("sameOrInside")
	}
}

func TestTableFileNamesMatchThePlugin(t *testing.T) {
	// PHP's preg_replace('/[^A-Za-z0-9_$-]/', '_') works on bytes: "é" is two.
	for in, want := range map[string]string{"wp_posts": "wp_posts", "wp_café": "wp_caf__", "a b$c-d": "a_b$c-d"} {
		if got := tableFileName(in); got != want {
			t.Errorf("tableFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecondReadIsCheckedAgain(t *testing.T) {
	r := &rehash{r: bytes.NewReader([]byte("changed")), h: sha256.New(), part: Part{Path: "files/x", SHA256: strings.Repeat("0", 64)}}
	if _, err := io.ReadAll(r); err == nil || !strings.Contains(err.Error(), "changed while it was being read") {
		t.Fatalf("got %v", err)
	}
}

func TestSizeChecksCannotOverflow(t *testing.T) {
	g := &entryGuard{part: Part{Path: "files/part-0001.tar", BytesRaw: 5}}
	if _, err := g.check(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.check(&tar.Header{Name: "b", Typeflag: tar.TypeReg, Size: math.MaxInt64 - 4}); err == nil {
		t.Fatal("a size that wraps the total around was accepted")
	}
	m := &Manifest{Parts: []Part{{Type: TypeFiles, BytesRaw: math.MaxInt64}, {Type: TypeFiles, BytesRaw: math.MaxInt64}}}
	if got := ExtractNeeds(m, ExtractOptions{Files: true}); got != math.MaxInt64 {
		t.Fatalf("ExtractNeeds = %d", got)
	}
	if _, err := g.check(&tar.Header{Name: strings.Repeat("a/", MaxPath/2+1), Typeflag: tar.TypeDir}); err == nil {
		t.Fatal("a path longer than MaxPath was accepted")
	}
}

func TestLinksNeverPassThroughExistingLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s3cret"), 0o600)
	dest := filepath.Join(base, "site")
	os.MkdirAll(filepath.Join(dest, "wp-content"), 0o755)
	os.Symlink(outside, filepath.Join(dest, "wp-content", "up")) // Already there: never checked.
	path := tArchive{parts: []tPart{filesPart(t, tEntry{name: "x", typ: tar.TypeSymlink, link: "up/secret"})}}.build(t)
	var warns []string
	st, err := openT(t, path).Extract("", ExtractOptions{Dest: dest, Files: true, Symlinks: true, Force: true, Warn: func(s string) { warns = append(warns, s) }})
	if err != nil || st.Symlinks != 0 || len(warns) != 1 || !strings.Contains(warns[0], "existing link") {
		t.Fatalf("%v %+v %v", err, st, warns)
	}
	if _, err := SymlinkTarget("l", "a/.. /x"); err == nil {
		t.Fatal(`".. " (a climb on Windows) was accepted`)
	}
}
