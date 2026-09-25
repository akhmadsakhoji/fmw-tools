# Contributing

Thank you for helping. Issues and pull requests are welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems go through [SECURITY.md](SECURITY.md), never public issues.
- FMW Tools reads the archive format specified in the plugin repository ([docs/format-v1.md](https://github.com/akhmadsakhoji/founders-migration-website/blob/main/docs/format-v1.md)). Behaviour that depends on the format follows that document; if they disagree, open an issue.

## Setup

Go 1.24 or newer:

```bash
git clone https://github.com/<your-fork>/fmw-tools.git
cd fmw-tools
go test ./...
go vet ./... && gofmt -l .
```

CI runs the same checks on Linux, macOS and Windows, and cross-compiles every release target.

## Code rules

- **Standard library only.** No third-party modules: a program that opens backups of whole websites should have as little supply chain as possible.
- **Archive input is untrusted.** Validate every path with `SafeRelative` and every link with `SymlinkTarget`; never use part content before `CheckPart` succeeded.
- **Stream.** Nothing may read a whole part or file into memory; memory must not grow with the size of a backup.
- **Tests.** New behaviour needs a test. Bugs get a failing test first. Hostile archives are built with the helpers in `internal/fmw/builder_test.go`.
- **File header.** Every Go file starts with:

```go
// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later
```

## Developer Certificate of Origin

Sign off every commit (`git commit -s`) to certify that you wrote the change or have the right to submit it under the project's license ([developercertificate.org](https://developercertificate.org/)).
