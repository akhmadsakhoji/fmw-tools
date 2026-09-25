// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

// Command fmw-tools inspects, verifies, decrypts and extracts Founders
// Migration Website backups (.fmw) without PHP or WordPress.
package main

import (
	"os"
	"runtime/debug"

	"github.com/akhmadsakhoji/fmw-tools/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = ""

func main() {
	if version == "" {
		version = "dev"
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version // go install github.com/akhmadsakhoji/fmw-tools/cmd/fmw-tools@v1.2.3
		}
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
