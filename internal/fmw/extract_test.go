// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var regexpDB = regexp.MustCompile(`^database/(\d{4})-.+\.(\d{4})\.sql\.gz$`)

// extractT extracts into a fresh "site" folder that sits next to an "outside" folder.
func extractT(t *testing.T, path, password string, o ExtractOptions) (string, string, *ExtractStats, []string, error) {
	t.Helper()
	base := t.TempDir()
	dest := filepath.Join(base, "site")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(outside, 0o755)
	a := openT(t, path)
	var warnings []string
	o.Dest = dest
	o.Warn = func(s string) { warnings = append(warnings, s) }
	if !o.Files && !o.Database && !o.Root {
		o.Files, o.Database, o.Root = true, true, true
	}
	st, err := a.Extract(password, o)
	return dest, outside, st, warnings, err
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	items, _ := os.ReadDir(dir)
	if len(items) > 0 {
		t.Fatalf("%s should be empty, has %v", dir, items)
	}
	parent := filepath.Dir(filepath.Dir(dir))
	if _, err := os.Stat(filepath.Join(parent, "evil")); err == nil {
		t.Fatal("a file was written above the extraction folder")
	}
}

func TestExtractPluginFixturesMatch(t *testing.T) {
	plainDest, _, st, warns, err := extractT(t, plainFixture, "", ExtractOptions{Symlinks: true})
	if err != nil || len(warns) > 0 {
		t.Fatalf("plain: %v %v", err, warns)
	}
	if st.Files != 4 || st.Dirs != 1 || st.SQLFiles != 16 || st.ContentDir != "wp-content" {
		t.Fatalf("plain stats: %+v", st)
	}
	encDest, _, st2, _, err := extractT(t, encryptedFixture, fixturePassword, ExtractOptions{Symlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if st2.Files != st.Files || st2.Dirs != st.Dirs || st2.SQLFiles != st.SQLFiles {
		t.Fatalf("encrypted stats %+v differ from plain %+v", st2, st)
	}
	// Both backups were made in the same second: the files are identical.
	for _, rel := range []string{"wp-content/index.php", "wp-content/database/.ht.sqlite", "wp-content/database/.htaccess"} {
		a, _ := os.ReadFile(filepath.Join(plainDest, rel))
		b, _ := os.ReadFile(filepath.Join(encDest, rel))
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Fatalf("%s differs or is empty", rel)
		}
	}
	for _, rel := range []string{"database/0006-wp_options.0001.sql.gz", "database/0016-views.0001.sql.gz", "fmw-manifest.json"} {
		if _, err := os.Stat(filepath.Join(encDest, rel)); err != nil {
			t.Fatalf("missing %s", rel)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(plainDest, "wp-content/database"))
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("folder mode %v, want 0700 as archived", info.Mode().Perm())
		}
	}
}

func TestExtractRefusesUnsafePaths(t *testing.T) {
	for _, name := range []string{"../evil", "uploads/../../evil", "/tmp/evil", `uploads\..\evil`, "C:/evil"} {
		path := tArchive{parts: []tPart{filesPart(t, tEntry{name: "ok.txt", body: "fine"}, tEntry{name: name, body: "bad"})}}.build(t)
		dest, outside, _, _, err := extractT(t, path, "", ExtractOptions{})
		if err == nil || !strings.Contains(err.Error(), "archive path") {
			t.Fatalf("%q: expected refusal, got %v", name, err)
		}
		assertEmpty(t, outside)
		if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil")); err == nil {
			t.Fatalf("%q escaped", name)
		}
	}
}

func TestExtractRefusesEscapingSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}
	path := tArchive{parts: []tPart{filesPart(t,
		tEntry{name: "up", typ: tar.TypeSymlink, link: "../../outside"},        // Climbs out.
		tEntry{name: "abs", typ: tar.TypeSymlink, link: "/etc"},                // Absolute.
		tEntry{name: "here", typ: tar.TypeSymlink, link: "."},                  // Fine on its own...
		tEntry{name: "chain", typ: tar.TypeSymlink, link: "here/../.."},        // ...but this goes through it to the parent.
		tEntry{name: "uploads/ok", typ: tar.TypeSymlink, link: "../index.php"}, // Fine.
		tEntry{name: "index.php", body: "<?php"},
	)}}.build(t)
	dest, outside, st, warns, err := extractT(t, path, "", ExtractOptions{Symlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Symlinks != 2 || st.Skipped != 3 || len(warns) != 3 {
		t.Fatalf("stats %+v warnings %v", st, warns)
	}
	for _, bad := range []string{"up", "abs", "chain"} {
		if _, err := os.Lstat(filepath.Join(dest, "wp-content", bad)); err == nil {
			t.Fatalf("link %s was created", bad)
		}
	}
	if target, err := os.Readlink(filepath.Join(dest, "wp-content/uploads/ok")); err != nil || target != "../index.php" {
		t.Fatalf("good link: %q %v", target, err)
	}
	assertEmpty(t, outside)
}

func TestExtractNeverWritesThroughLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}
	// A link in the archive followed by files "inside" it: the files land in
	// a real folder (links are created last), and the link is then skipped.
	path := tArchive{parts: []tPart{filesPart(t,
		tEntry{name: "uploads", typ: tar.TypeSymlink, link: "cache"},
		tEntry{name: "uploads/photo.jpg", body: "jpg"},
	)}}.build(t)
	dest, _, st, warns, err := extractT(t, path, "", ExtractOptions{Symlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dest, "wp-content/uploads"))
	if err != nil || !info.IsDir() || st.Symlinks != 0 || len(warns) != 1 {
		t.Fatalf("uploads should be a real folder: %v %v %+v %v", info, err, st, warns)
	}

	// A link already in the destination (with --force) is never followed.
	path = tArchive{parts: []tPart{filesPart(t, tEntry{name: "plugins/evil.php", body: "x"})}}.build(t)
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	os.MkdirAll(outside, 0o755)
	dest = filepath.Join(base, "site")
	os.MkdirAll(dest, 0o755)
	if err := os.Symlink(outside, filepath.Join(dest, "wp-content")); err != nil {
		t.Fatal(err)
	}
	a := openT(t, path)
	_, err = a.Extract("", ExtractOptions{Dest: dest, Files: true, Force: true, Warn: func(string) {}})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected refusal, got %v", err)
	}
	assertEmpty(t, outside)
}

func TestExtractChecksPartsBeforeUse(t *testing.T) {
	parts := []tPart{sqlPart(1, "wp_options", "SET NAMES utf8mb4;"), filesPart(t, tEntry{name: "a.txt", body: "a"})}
	for _, password := range []string{"", "secret"} {
		ps := parts
		if password != "" {
			ps = encryptedNames(parts)
		}
		// Flip one byte of the files part after its checksums were recorded.
		path := tArchive{parts: ps, password: password, mutate: func(name string, data []byte) []byte {
			if strings.HasPrefix(name, "files/") {
				data = append([]byte{}, data...)
				data[len(data)-3] ^= 1
			}
			return data
		}}.build(t)
		dest, _, _, _, err := extractT(t, path, password, ExtractOptions{})
		var pe *PartError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatalf("password %q: expected checksum error, got %v", password, err)
		}
		if _, err := os.Stat(filepath.Join(dest, "wp-content/a.txt")); err == nil {
			t.Fatal("content of a damaged part was written")
		}
	}
}

func TestExtractPathFilterAndPlainSQL(t *testing.T) {
	path := tArchive{parts: []tPart{
		sqlPart(1, "wp_options", "SET NAMES utf8mb4;\n"),
		filesPart(t,
			tEntry{name: "uploads/2025/01/a.jpg", body: "a"},
			tEntry{name: "uploads/2025/02/b.jpg", body: "bb"},
			tEntry{name: "uploads/2025/012/c.jpg", body: "c"},
			tEntry{name: "plugins/x.php", body: "x"},
		),
	}}.build(t)
	dest, _, st, _, err := extractT(t, path, "", ExtractOptions{Files: true, Paths: []string{"uploads/2025/01/"}})
	if err != nil || st.Files != 1 || st.SQLFiles != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "wp-content/uploads/2025/01/a.jpg")); err != nil {
		t.Fatal(err)
	}
	dest, _, _, _, err = extractT(t, path, "", ExtractOptions{Database: true, PlainSQL: true})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "database/0001-wp_options.0001.sql")); string(b) != "SET NAMES utf8mb4;\n" {
		t.Fatalf("plain SQL: %q", b)
	}
}

func TestExtractRefusesNonEmptyFolder(t *testing.T) {
	dest := t.TempDir()
	os.WriteFile(filepath.Join(dest, "keep.txt"), []byte("x"), 0o644)
	a := openT(t, plainFixture)
	if _, err := a.Extract("", ExtractOptions{Dest: dest, Files: true}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "keep.txt")); string(b) != "x" {
		t.Fatal("existing file changed")
	}
}

func TestExtractFileModesAreSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := tArchive{parts: []tPart{filesPart(t, tEntry{name: "s.sh", body: "#!/bin/sh", mode: 0o4755})}}.build(t)
	dest, _, _, _, err := extractT(t, path, "", ExtractOptions{Files: true})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dest, "wp-content/s.sh"))
	if info.Mode()&fs.ModeSetuid != 0 || info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", info.Mode())
	}
}
