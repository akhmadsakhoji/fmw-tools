# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `fmw-tools inspect`: site, WordPress, PHP and database versions, exclusions, contents and sizes of a backup; only the date without the password of an encrypted one. `--json` for scripts.
- `fmw-tools verify`: size, SHA-256 and (encrypted backups) HMAC of every part, missing and unexpected entries. `--deep` also decrypts and unpacks every part and checks gzip checksums, TAR structure, entry paths, entry counts and data sizes against the manifest.
- `fmw-tools list`: the parts, or with `--files` every file, folder and link (`--long`, `--path`, `--json` as JSON Lines).
- `fmw-tools extract`: files into `<folder>/wp-content`, the database into `<folder>/database` (`--sql=gz|plain`), with `--only=files,database,root` and `--path` to restore single files or folders. Each part is checked before use and hashed again while it is used. Paths are confined to the folder; links are created last and only with relative targets that stay inside and use `..` only at the start (safe on case-insensitive file systems); nothing is written through an existing link. Root files are limited to the format's allowlist, permissions are masked like a umask of 022, sparse files and parts holding more data than their manifest records are refused, and free disk space is checked first (`--skip-space-check`).
- Text from backups is printed with control characters and bidirectional overrides replaced, so a crafted file name cannot rewrite the terminal.
- `fmw-tools decrypt`: an unencrypted copy of a password-protected backup, restorable by the plugin (`wp fmw restore`) or by hand. Parts are authenticated before decryption, decrypted sizes are checked, table names come back in the database part names, and unknown manifest keys and key order are kept.
- Format v1 reader: TAR containers and directory mode, OpenSSL-compatible AES-256-CBC with PBKDF2-HMAC-SHA256 (600,000 iterations by default) and HMAC-SHA256, strict checks of part names, types, compressions and newer format versions (exit code 4).
- Passwords from a no-echo prompt (Linux, macOS, FreeBSD, Windows), `--password-file` or `FMW_PASSWORD`; keys of all parts derived in parallel.
- Progress bar with speed and time left; exit codes 0 ok, 1 damaged or failed, 2 usage, 3 password, 4 newer format.
- Release builds for Linux, macOS and Windows (amd64 and arm64) with SHA-256 checksums and signed build provenance; CI on all three systems.
