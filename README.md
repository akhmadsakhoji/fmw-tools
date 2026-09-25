# FMW Tools

Inspect, verify, decrypt and extract **Founders Migration Website** backups (`.fmw`) without PHP, WordPress or a web server.

[Founders Migration Website](https://github.com/akhmadsakhoji/founders-migration-website) (FMW) is a WordPress backup and migration plugin for sites up to 100 GB and beyond. FMW Tools is its companion program for when the backup is all you have: on your laptop, on a new server, or next to a site that no longer starts.

- **One file, no dependencies.** A single program for Windows, macOS and Linux, built only on the Go standard library. Nothing to install and no network access.
- **Checks before it trusts.** Every part is checked against the manifest (size, SHA-256 and, for encrypted backups, HMAC) before its content is used.
- **Opens password-protected backups.** It can decrypt a backup to a plain copy that the plugin or `tar`, `gzip` and `mysql` can restore, or extract straight from the encrypted file.
- **Safe to point at any file.** Paths stay inside the target folder, links that point outside are refused, and nothing is ever written through a link.
- **Built for big archives.** Everything streams with a small, constant amount of memory, and key derivation runs on every CPU core.

```text
$ fmw-tools inspect example.com-20260924-180000-a1b2c3.fmw
File:            example.com-20260924-180000-a1b2c3.fmw (81.2 GB)
Format:          FMW v1, written by fmw/1.0.0 on 2026-09-24 18:00:00 UTC
Encrypted:       no
Site:            https://example.com
WordPress:       7.0, PHP 8.3.12
Database:        mariadb 10.11.8, utf8mb4 / utf8mb4_unicode_520_ci, table prefix wp_
Multisite:       no
Theme:           astra-child (child of astra)
Active plugins:  23
Excluded:        cache, spam-comments
Contents:        184,213 files, 62 tables, 1,204,331 rows
Size:            98.2 GB of data, 81.2 GB stored
Parts:           131 (48 database, 83 files)
```

## Install

Download the archive for your system from the [latest release](https://github.com/akhmadsakhoji/fmw-tools/releases/latest):

| System | File |
|---|---|
| Windows (Intel/AMD) | `fmw-tools_<version>_windows_amd64.zip` |
| Windows (ARM) | `fmw-tools_<version>_windows_arm64.zip` |
| macOS (Apple silicon) | `fmw-tools_<version>_darwin_arm64.tar.gz` |
| macOS (Intel) | `fmw-tools_<version>_darwin_amd64.tar.gz` |
| Linux (x86-64) | `fmw-tools_<version>_linux_amd64.tar.gz` |
| Linux (ARM64) | `fmw-tools_<version>_linux_arm64.tar.gz` |

Linux and macOS:

```bash
tar -xzf fmw-tools_*_linux_amd64.tar.gz
sudo mv fmw-tools_*/fmw-tools /usr/local/bin/
fmw-tools version
```

On macOS the program is not notarized by Apple yet. The first time, remove the download quarantine flag: `xattr -d com.apple.quarantine /usr/local/bin/fmw-tools`.

On Windows, unzip the file and run `.\fmw-tools.exe` in PowerShell, or put the folder in your `PATH`.

**Check your download.** Every release lists SHA-256 checksums (`sha256sum -c SHA256SUMS --ignore-missing`), and its files carry signed build provenance from GitHub Actions: `gh attestation verify <file> -R akhmadsakhoji/fmw-tools`.

**From source** (Go 1.24 or newer): `go install github.com/akhmadsakhoji/fmw-tools/cmd/fmw-tools@latest`.

## Usage

```text
fmw-tools <command> [options] <archive.fmw>
```

| Command | What it does |
|---|---|
| `inspect` | Shows the site, versions, what was excluded and the sizes; for a multisite network also its address, kind, main site and sites (`--sites` for all). Without the password of an encrypted backup, only its date is readable. |
| `verify` | Checks every part: size, SHA-256 and, when encrypted, HMAC. `--deep` also decrypts and unpacks every part and checks its content. |
| `list` | Lists the parts. `--files` lists every file, folder and link (`--long` for details, `--path` to narrow it down). |
| `extract` | Unpacks the files and the database into a folder, or only one site of a network (`--site`). |
| `decrypt` | Writes an unencrypted copy of a password-protected backup. |
| `help <command>` | All options of a command. |

Options may come before or after the file names.

```bash
fmw-tools verify backup.fmw --deep                       # full check, reads the archive twice
fmw-tools list backup.fmw --files --path uploads/2025/01 # what is in that folder
fmw-tools extract backup.fmw ./restore                   # everything
fmw-tools extract backup.fmw ./restore --path uploads/2025/01/photo.jpg   # one file
fmw-tools extract backup.fmw ./restore --only database --sql plain       # only the SQL, uncompressed
fmw-tools extract network.fmw ./shop --site example.com/shop             # one site of a network backup
fmw-tools decrypt backup-20260924-180000-a1b2c3.fmw      # -> example.com-20260924-180000-a1b2c3.fmw
```

`extract` lays the folder out like a WordPress root:

```text
restore/
├── wp-content/            plugins, themes, uploads, ... (only what the backup holds)
├── database/              0001-wp_options.0001.sql.gz, ...  in restore order
└── fmw-manifest.json      source URLs, paths, versions and checksums
```

Import the database in file name order, then replace the old address if the domain changed:

```bash
for f in restore/database/*.sql.gz; do gunzip -c "$f"; done | mysql -u USER -p DB_NAME
wp search-replace 'https://old.example.com' 'https://new.example.com' --all-tables
```

The folder must be empty, unless you pass `--force`; files from the backup then replace existing ones. Before writing, `extract` checks that the disk has room for the data (not with `--path` or `--site`, which take only part of it).

### Multisite networks

Backups of a whole network (subdomains or subdirectories, plain or encrypted) work with every command. `inspect` shows the network:

```text
Multisite:       yes, 16 sites (subdirectories)
Network:         example.com/, main site 1
Sites:           1    example.com/
                 2    example.com/shop/
                 3    example.com/news/
```

Backups made before the plugin recorded the network (`site.network` in the manifest) get it worked out from their sites; `inspect` says so.

`extract --site=<id, address or short name>` unpacks only one site (`2`, `example.com/shop`, `shop.example.com`, or just `shop` when only one site has that folder or subdomain): its own tables (`wp_2_*`; site 1 has the bare prefix `wp_*`), the users (`wp_users`, `wp_usermeta`, shared by the network), its media (`uploads/sites/2/`, `blogs.dir/2/files/` on old networks, or `uploads/` itself for the main site) and the files all sites share (plugins, themes, languages). The network's own tables, other sites' tables and media, and the network's views and triggers stay in the backup. Names and paths stay as they are in the network; to turn the site into a single site (tables `wp_2_posts` → `wp_posts`, media to `uploads/`, users with a role on it), restore the backup with the plugin: `wp fmw restore network.fmw --site=2`.

When a whole network is imported by hand at another address, set the new domain and path in the `wp_blogs` and `wp_site` tables (bare domains and paths, not URLs) and in `DOMAIN_CURRENT_SITE` / `PATH_CURRENT_SITE` in `wp-config.php`, besides `wp search-replace --network`; `extract` reminds you.

### Passwords

For an encrypted backup the password is asked for without echo. In scripts, use `--password-file=<file>` (first line) or the `FMW_PASSWORD` environment variable. `--password=<password>` works too, but other users of the machine can see it in the process list, and it stays in your shell history.

A wrong password is detected right away through the manifest's HMAC, before any heavy work. Deriving the key of each part takes about a second of CPU time (PBKDF2 with 600,000 iterations, as the plugin writes them); FMW Tools derives the keys of all parts in parallel.

### Scripts

`inspect --json`, `verify --json` and `list --json` print machine-readable output (`list --files --json` prints one JSON object per line). The exit code says how it went:

| Code | Meaning |
|---|---|
| 0 | Done; the archive is intact. |
| 1 | The archive is damaged or incomplete, or the work failed. |
| 2 | Wrong command line (unknown option, target folder not empty, output exists). |
| 3 | Password missing or wrong. |
| 4 | The archive needs a newer FMW Tools. |

## Safety

- **The backup is only read.** No command changes the `.fmw` file, and `decrypt` refuses to write its copy over the backup or inside it.
- **Nothing is used before it is checked.** Each part's size and SHA-256 are compared with the manifest (whose own HMAC is checked first for encrypted backups), and encrypted parts are also checked against their HMAC. `extract`, `list --files`, `decrypt` and `verify --deep` read each part twice, once to check it and once to use it, and hash it again while using it, so a part that changes in between (a synced or shared folder) is caught.
- **Extraction stays in its folder.** Absolute paths, drive letters, `..` segments and backslashes stop the extraction. Links are created after every file and folder, and only when their target is relative, stays inside the folder and uses `..` only at the start. That rule makes chains of links safe on case-insensitive file systems (macOS, Windows) too. Links already in the folder are never written through, and no link from the backup may point through them.
- **No surprises in what is written.** Only `.htaccess`, `robots.txt`, `ads.txt`, `google*.html` and `BingSiteAuth.xml` go to the WordPress root (never `wp-config.php`). Permissions are applied like a umask of 022 (nothing writable by others, no set-user-ID). On Windows, names Windows cannot store (reserved names, `:` for alternate data streams, trailing dots) are skipped with a warning.
- **Bounded work.** Sparse files and paths longer than 4,096 bytes are refused, a part may not hold more data than its manifest records (this stops gzip bombs), and `extract` compares the size of the data with the free disk space first (`--skip-space-check` to try anyway).
- **Nothing hostile reaches your terminal.** Names and texts from the backup are printed with control characters and bidirectional overrides replaced.
- **`decrypt` writes to `<output>.partial` and renames it when complete,** so an interrupted run never leaves a file that looks finished. The copy has no password: store and share it with care.
- **No network, no telemetry, no third-party code.**

## Performance

Measured on a 2-core cloud VM with a 630 MB backup (2,390 files, 16 tables, 18 parts):

| Operation | Unencrypted | Encrypted |
|---|---|---|
| `verify` | 2.0 s | 13.3 s |
| `verify --deep` | 4.2 s | 16.0 s |
| `extract` | 4.7 s | 16.1 s |
| `decrypt` | — | 18.4 s |

Memory stayed around 13 MB; it does not grow with the size of the backup, because everything streams. For encrypted backups most of the time is key derivation: about a second of CPU time per part, spread over all cores, and independent of the part size. Everything else is limited by the disk; a 100 GB backup takes about as long as reading it once (`verify`) or twice (`extract`, `decrypt`).

## Compatibility

- Reads archive format v1 as written by the plugin: TAR containers and directory mode (the same entries as plain files in a folder). The format is documented in [docs/format-v1.md](https://github.com/akhmadsakhoji/founders-migration-website/blob/main/docs/format-v1.md) of the plugin; newer format versions are refused with exit code 4 rather than misread.
- All-in-One WP Migration `.wpress` files are not supported here; restore them with the plugin (`wp fmw restore site.wpress`).

## Development

```bash
go test ./...                      # unit tests, including hostile archives
go vet ./... && gofmt -l .
scripts/build-release.sh v0.0.0    # every release archive into dist/
```

The files in `testdata/` are real backups written by the plugin (password of `encrypted.fmw`: `fmw-tools test 1`). Pushing a tag like `v0.1.0` builds and publishes a release.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

GPL-2.0-or-later. Copyright (C) 2026 PT Founder Media Partner. See [LICENSE](LICENSE).
