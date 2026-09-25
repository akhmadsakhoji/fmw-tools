// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

// Package cli is the fmw-tools command line.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/akhmadsakhoji/fmw-tools/internal/fmw"
)

// Exit codes.
const (
	ExitOK       = 0 // Done; the archive is intact.
	ExitProblem  = 1 // The archive is damaged or incomplete, or the work failed.
	ExitUsage    = 2 // Wrong command line.
	ExitPassword = 3 // Password missing or wrong.
	ExitNewer    = 4 // The archive needs a newer FMW Tools.
)

const usage = `FMW Tools %s: inspect, verify, decrypt and extract Founders Migration
Website backups (.fmw) without PHP or WordPress.

Usage:
  fmw-tools <command> [options] <archive.fmw>

Commands:
  inspect   Show what a backup holds: site, versions, what was excluded, sizes
  verify    Check every part (size, SHA-256, HMAC); --deep also unpacks them
  list      List the parts, or with --files every file in the backup
  extract   Unpack the files and the database into a folder
  decrypt   Write an unencrypted copy of a password-protected backup
  version   Show the version
  help      Show help for a command: fmw-tools help extract

Passwords (encrypted backups) are asked for without echo, or read from
--password-file=<file> or the FMW_PASSWORD environment variable.

Exit codes: 0 ok, 1 damaged archive or failure, 2 wrong usage,
3 missing or wrong password, 4 archive needs a newer FMW Tools.
`

// Run runs one command and returns the exit code.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	fmw.Generator = "fmw-tools/" + version
	r := &runner{out: stdout, err: stderr, version: version, stdin: os.Stdin, stderrFile: os.Stderr}
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "inspect", "info":
		return r.inspect(rest)
	case "verify", "check":
		return r.verify(rest)
	case "list", "ls":
		return r.list(rest)
	case "extract", "x":
		return r.extract(rest)
	case "decrypt":
		return r.decrypt(rest)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "fmw-tools %s (%s, %s/%s), archive format v%d\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH, fmw.SupportedVersion)
		return ExitOK
	case "help", "--help", "-h":
		if len(rest) > 0 && rest[0] != "help" {
			return Run([]string{rest[0], "--help"}, stdout, stderr, version)
		}
		fmt.Fprintf(stdout, usage, version)
		return ExitOK
	}
	fmt.Fprintf(stderr, "fmw-tools: unknown command %q\n\n", cmd)
	fmt.Fprintf(stderr, usage, version)
	return ExitUsage
}

type runner struct {
	out, err   io.Writer
	version    string
	stdin      *os.File
	stderrFile *os.File

	password     string
	passwordFile string
	quiet        bool
}

// flags creates a command's option set with the shared options.
func (r *runner) flags(name, args, help string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.err)
	fs.StringVar(&r.passwordFile, "password-file", "", "read the password from the first line of this file")
	fs.StringVar(&r.password, "password", "", "the password (visible in the process list and shell history; prefer --password-file)")
	fs.BoolVar(&r.quiet, "quiet", false, "no progress bar")
	fs.Usage = func() {
		fmt.Fprintf(r.err, "Usage: fmw-tools %s %s\n\n%s\n\nOptions:\n", name, args, help)
		fs.PrintDefaults()
	}
	return fs
}

func (r *runner) parse(fs *flag.FlagSet, args []string, min, max int) ([]string, int) {
	pos, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return nil, ExitOK
	}
	if err != nil {
		return nil, ExitUsage
	}
	if len(pos) < min || len(pos) > max {
		fs.Usage()
		return nil, ExitUsage
	}
	return pos, -1
}

// fail prints an error and maps it to an exit code.
func (r *runner) fail(err error) int {
	fmt.Fprintln(r.err, "fmw-tools: "+clean(err.Error())) // Errors can quote paths from the archive.
	var unsupported *fmw.UnsupportedError
	switch {
	case errors.Is(err, fmw.ErrPasswordRequired), errors.Is(err, fmw.ErrWrongPassword):
		return ExitPassword
	case errors.As(err, &unsupported):
		return ExitNewer
	}
	return ExitProblem
}

func (r *runner) progressOn() bool { return !r.quiet && isTerminal(r.stderrFile) }

// open opens the archive and, for encrypted ones, gets the password and the manifest.
// With optional, a missing password is not an error (the manifest is then nil).
func (r *runner) open(path string, optional bool) (*fmw.Archive, *fmw.Manifest, error) {
	a, err := fmw.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if !a.Encrypted() {
		m, err := a.Manifest("")
		if err != nil {
			a.Close()
			return nil, nil, err
		}
		return a, m, nil
	}
	password, err := r.givenPassword()
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	if password != "" {
		m, err := a.Manifest(password)
		if err != nil {
			a.Close()
			return nil, nil, err
		}
		return a, m, nil
	}
	if !isTerminal(r.stdin) {
		if optional {
			return a, nil, nil
		}
		a.Close()
		return nil, nil, fmt.Errorf("%w: use --password-file=<file> or the FMW_PASSWORD environment variable", fmw.ErrPasswordRequired)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Fprint(r.err, "Password: ")
		pw, err := readPassword(r.stdin)
		fmt.Fprintln(r.err)
		if err != nil || pw == "" {
			if optional {
				return a, nil, nil
			}
			a.Close()
			return nil, nil, fmw.ErrPasswordRequired
		}
		m, err := a.Manifest(pw)
		if err == nil {
			return a, m, nil
		}
		if !errors.Is(err, fmw.ErrWrongPassword) || attempt == 3 {
			a.Close()
			return nil, nil, err
		}
		fmt.Fprintln(r.err, "Wrong password, try again.")
	}
	a.Close()
	return nil, nil, fmw.ErrWrongPassword
}

// givenPassword is the password from --password, --password-file or FMW_PASSWORD ("" for none).
func (r *runner) givenPassword() (string, error) {
	if r.password != "" {
		return r.password, nil
	}
	if r.passwordFile != "" {
		f, err := os.Open(r.passwordFile)
		if err != nil {
			return "", err
		}
		defer f.Close()
		line, err := readLine(f)
		if err != nil || line == "" {
			return "", fmt.Errorf("%s holds no password", r.passwordFile)
		}
		return line, nil
	}
	return os.Getenv("FMW_PASSWORD"), nil
}

func (r *runner) printJSON(v any) int {
	enc := json.NewEncoder(r.out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return r.fail(err)
	}
	return ExitOK
}

func (r *runner) warn(msg string) { fmt.Fprintln(r.err, "warning: "+clean(msg)) }

func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return thousands(n) + " " + many
}

func joinNonEmpty(sep string, items ...string) string {
	var out []string
	for _, s := range items {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}
