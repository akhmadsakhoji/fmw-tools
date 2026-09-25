// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package cli

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	plain     = "../../testdata/plain.fmw"
	encrypted = "../../testdata/encrypted.fmw"
	password  = "fmw-tools test 1"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb, "test")
	return code, out.String(), errb.String()
}

func TestParseArgsAcceptsOptionsAnywhere(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	deep := fs.Bool("deep", false, "")
	file := fs.String("password-file", "", "")
	var paths listFlag
	fs.Var(&paths, "path", "")
	pos, err := parseArgs(fs, []string{"a.fmw", "--deep", "--password-file", "pw.txt", "out", "--path=uploads,plugins/x", "--path", "themes", "--", "--literal"})
	if err != nil || !*deep || *file != "pw.txt" || strings.Join(pos, "|") != "a.fmw|out|--literal" || paths.String() != "uploads,plugins/x,themes" {
		t.Fatalf("pos %v deep %v file %q paths %v err %v", pos, *deep, *file, paths, err)
	}
}

func TestExitCodes(t *testing.T) {
	t.Setenv("FMW_PASSWORD", "")
	cases := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{}, ExitUsage, ""},
		{[]string{"frobnicate"}, ExitUsage, ""},
		{[]string{"verify"}, ExitUsage, ""},
		{[]string{"version"}, ExitOK, "fmw-tools test"},
		{[]string{"help", "extract"}, ExitOK, ""},
		{[]string{"verify", plain}, ExitOK, "OK: 17 parts"},
		{[]string{"verify", "missing.fmw"}, ExitProblem, ""},
		{[]string{"verify", "cli_test.go"}, ExitProblem, ""},
		{[]string{"verify", encrypted}, ExitPassword, ""},
		{[]string{"verify", encrypted, "--password=wrong"}, ExitPassword, ""},
		{[]string{"verify", "--deep", encrypted, "--password", password}, ExitOK, "SHA-256 and HMAC match"},
		{[]string{"inspect", encrypted}, ExitOK, "600,000 iterations"},
		{[]string{"inspect", plain}, ExitOK, "http://127.0.0.1:8090"},
		{[]string{"decrypt", plain}, ExitUsage, ""},
		{[]string{"list", plain}, ExitOK, "database/0016-views.0001.sql.gz"},
		{[]string{"list", plain, "--files", "--path", "database"}, ExitOK, "database/.ht.sqlite"},
		{[]string{"list", plain, "--files", "--path", "nothing-here"}, ExitProblem, ""},
		{[]string{"extract", plain, t.TempDir(), "--sql=xz"}, ExitUsage, ""},
		{[]string{"extract", plain, t.TempDir(), "--only=media"}, ExitUsage, ""},
	}
	for _, c := range cases {
		code, out, errs := run(t, c.args...)
		if code != c.code || !strings.Contains(out, c.out) {
			t.Errorf("%v: exit %d (want %d)\nstdout: %s\nstderr: %s", c.args, code, c.code, out, errs)
		}
	}
}

func TestPasswordFileAndEnvironment(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pw.txt")
	os.WriteFile(file, []byte(password+"\r\n"), 0o600)
	if code, out, errs := run(t, "inspect", encrypted, "--password-file", file); code != ExitOK || !strings.Contains(out, "Site:") {
		t.Fatalf("password file: %d %s %s", code, out, errs)
	}
	t.Setenv("FMW_PASSWORD", password)
	if code, out, _ := run(t, "inspect", "--json", encrypted); code != ExitOK || !strings.Contains(out, `"manifest"`) {
		t.Fatalf("environment: %d %s", code, out)
	}
}

func TestExtractAndDecryptCommands(t *testing.T) {
	t.Setenv("FMW_PASSWORD", password)
	dir := t.TempDir()
	dest := filepath.Join(dir, "site")
	code, out, errs := run(t, "extract", encrypted, dest, "--only=files")
	if code != ExitOK || !strings.Contains(out, "Extracted 4 files and 1 folder") {
		t.Fatalf("extract: %d %s %s", code, out, errs)
	}
	if code, _, errs := run(t, "extract", encrypted, dest); code != ExitUsage || !strings.Contains(errs, "not empty") {
		t.Fatalf("non-empty folder: %d %s", code, errs)
	}

	copyPath := filepath.Join(dir, "backup-20260924-224438-3c6def.fmw")
	data, _ := os.ReadFile(encrypted)
	os.WriteFile(copyPath, data, 0o644)
	code, out, errs = run(t, "decrypt", copyPath)
	want := filepath.Join(dir, "127.0.0.1-20260924-224438-3c6def.fmw")
	if code != ExitOK || !strings.Contains(out, want) {
		t.Fatalf("decrypt: %d %s %s", code, out, errs)
	}
	if code, _, _ := run(t, "decrypt", copyPath); code != ExitUsage {
		t.Fatal("decrypt should refuse to replace the output without --force")
	}
	t.Setenv("FMW_PASSWORD", "")
	if code, out, errs := run(t, "verify", want, "--deep"); code != ExitOK {
		t.Fatalf("verify decrypted: %d %s %s", code, out, errs)
	}
}

func TestCleanStopsTerminalInjection(t *testing.T) {
	for in, want := range map[string]string{
		"uploads/foto é.jpg":          "uploads/foto é.jpg",
		"a\x1b]0;owned\x07b":          "a?]0;owned?b",
		"x\x1b[2Jy":                   "x?[2Jy",
		"invoice‮fdp.exe":             "invoice?fdp.exe",
		"bad\xffutf8":                 "bad?utf8",
		"https://example.com\r\nX: 1": "https://example.com??X: 1",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErrorsAndWarningsAreCleaned(t *testing.T) {
	var errb bytes.Buffer
	r := &runner{err: &errb}
	r.fail(errors.New("lstat x\x1b]0;PWNED\a"))
	r.warn("skipped \x1b[2J")
	if strings.ContainsAny(errb.String(), "\x1b\a") {
		t.Fatalf("escape reached the terminal: %q", errb.String())
	}
}

func TestSiteChoiceNeedsANetworkBackup(t *testing.T) {
	code, out, errs := run(t, "extract", "--site=2", plain, t.TempDir())
	if code != ExitUsage || !strings.Contains(errs, "--site is for backups of a multisite network") || out != "" {
		t.Fatalf("code %d out %q err %q", code, out, errs)
	}
	for _, empty := range [][]string{{"extract", "--site=", plain, t.TempDir()}, {"extract", "--site", "", plain, t.TempDir()}} {
		if code, _, errs := run(t, empty...); code != ExitUsage || !strings.Contains(errs, "--site is empty") {
			t.Fatalf("empty --site: %d %q", code, errs)
		}
	}
	code, out, _ = run(t, "inspect", "--sites", plain)
	if code != ExitOK || !strings.Contains(out, "Multisite:") || strings.Contains(out, "Sites:") {
		t.Fatalf("inspect: %d %q", code, out)
	}
}
