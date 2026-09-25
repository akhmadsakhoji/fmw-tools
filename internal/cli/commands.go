// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/akhmadsakhoji/fmw-tools/internal/fmw"
)

func (r *runner) inspect(args []string) int {
	fs := r.flags("inspect", "[options] <archive.fmw>", "Shows what a backup holds. Without the password of an encrypted backup only its date is readable.")
	asJSON := fs.Bool("json", false, "print fmw.json and the manifest as JSON")
	pos, code := r.parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	a, m, err := r.open(pos[0], true)
	if err != nil {
		return r.fail(err)
	}
	defer a.Close()

	if *asJSON {
		out := map[string]any{"file": pos[0], "header": json.RawMessage(a.RawHeader())}
		if m != nil {
			out["manifest"] = json.RawMessage(m.RawManifest())
		}
		return r.printJSON(out)
	}

	w := tabwriter.NewWriter(r.out, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(w, "%s:\t%s\n", k, clean(v)) // Values come from the archive.
		}
	}
	h := a.Header
	stored := ""
	if info, err := os.Stat(pos[0]); err == nil && !info.IsDir() {
		stored = " (" + size(info.Size()) + ")"
	}
	row("File", filepath.Base(pos[0])+stored)
	row("Format", fmt.Sprintf("FMW v%d, written by %s on %s", h.Version, h.Generator, when(h.CreatedAt)))
	if h.Encrypted {
		row("Encrypted", fmt.Sprintf("yes (AES-256-CBC, PBKDF2-SHA256 with %s iterations, HMAC-SHA256)", thousands(int64(h.KDF.Iterations))))
	} else {
		row("Encrypted", "no")
	}
	if m == nil {
		w.Flush()
		fmt.Fprintln(r.out, "\nThe site details are encrypted. Give the password (prompt, --password-file or FMW_PASSWORD) to see them.")
		return ExitOK
	}
	s := m.Site
	row("Site", s.HomeURL)
	if s.SiteURL != "" && s.SiteURL != s.HomeURL {
		row("WordPress address", s.SiteURL)
	}
	row("Source path", s.Abspath)
	row("WordPress", joinNonEmpty(", ", s.WPVersion, prefixed("PHP ", s.PHPVersion)))
	row("Database", joinNonEmpty(", ", joinNonEmpty(" ", s.DB.Engine, s.DB.Version), joinNonEmpty(" / ", s.DB.Charset, s.DB.Collate), prefixed("table prefix ", s.TablePrefix)))
	if s.Multisite {
		row("Multisite", fmt.Sprintf("yes, %s", plural(int64(len(s.Sites)), "site", "sites")))
	} else {
		row("Multisite", "no")
	}
	theme := s.Stylesheet
	if s.Template != "" && s.Template != s.Stylesheet {
		theme += " (child of " + s.Template + ")"
	}
	row("Theme", theme)
	row("Active plugins", fmt.Sprintf("%d", len(s.ActivePlugins)))
	excluded := append(append([]string{}, m.Options.Exclude...), prefixAll("table ", m.Options.ExcludeTables)...)
	excluded = append(excluded, prefixAll("path ", m.Options.ExcludePaths)...)
	if len(excluded) == 0 {
		excluded = []string{"nothing"}
	}
	row("Excluded", strings.Join(excluded, ", "))

	var db, files, root int64
	for _, p := range m.Parts {
		switch p.Type {
		case fmw.TypeDatabase:
			db++
		case fmw.TypeFiles:
			files++
		default:
			root++
		}
	}
	row("Contents", fmt.Sprintf("%s, %s, %s", plural(m.Totals.Files, "file", "files"), plural(m.Totals.Tables, "table", "tables"), plural(m.Totals.Rows, "row", "rows")))
	row("Size", fmt.Sprintf("%s of data, %s stored", size(m.Totals.BytesRaw), size(m.Totals.BytesArchived)))
	parts := fmt.Sprintf("%d (%d database, %d files", len(m.Parts), db, files)
	if root > 0 {
		parts += fmt.Sprintf(", %d root files", root)
	}
	row("Parts", parts+")")
	w.Flush()
	return ExitOK
}

func (r *runner) verify(args []string) int {
	fs := r.flags("verify", "[options] <archive.fmw>", "Checks every part against the manifest: size and SHA-256, and the HMAC of encrypted backups.\nWith --deep every part is also decrypted and unpacked, and its content checked.")
	deep := fs.Bool("deep", false, "also unpack every part and check its content (reads the archive twice)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, code := r.parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	a, m, err := r.open(pos[0], false)
	if err != nil {
		return r.fail(err)
	}
	defer a.Close()
	bar := newProgress(r.err, r.progressOn() && !*asJSON, "Verifying", fmw.VerifyTotal(m, *deep))
	rep, err := a.Verify("", *deep, bar.add)
	bar.finish()
	if err != nil {
		return r.fail(err)
	}
	if *asJSON {
		r.printJSON(rep)
		if !rep.OK() {
			return ExitProblem
		}
		return ExitOK
	}
	if !rep.OK() {
		for _, p := range rep.Problems {
			fmt.Fprintln(r.out, "PROBLEM: "+p)
		}
		fmt.Fprintf(r.out, "\n%s found in %s.\n", plural(int64(len(rep.Problems)), "problem", "problems"), filepath.Base(pos[0]))
		return ExitProblem
	}
	checks := "size and SHA-256"
	if a.Encrypted() {
		checks = "size, SHA-256 and HMAC"
	}
	how := ""
	if *deep {
		how = "; every part unpacked and its content checked"
	}
	fmt.Fprintf(r.out, "OK: %s (%s): %s match%s.\n", plural(int64(rep.Parts), "part", "parts"), size(rep.Bytes), checks, how)
	return ExitOK
}

func (r *runner) list(args []string) int {
	fs := r.flags("list", "[options] <archive.fmw>", "Lists the parts of a backup, or with --files every file, folder and link in it\n(paths relative to wp-content).")
	files := fs.Bool("files", false, "list the files instead of the parts")
	long := fs.Bool("long", false, "with --files: also show type, permissions, size and date")
	var paths listFlag
	fs.Var(&paths, "path", "with --files: only under this path, for example uploads/2025 (repeatable)")
	asJSON := fs.Bool("json", false, "print JSON (one object per line with --files)")
	pos, code := r.parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	a, m, err := r.open(pos[0], false)
	if err != nil {
		return r.fail(err)
	}
	defer a.Close()

	if !*files {
		if *asJSON {
			return r.printJSON(m.Parts)
		}
		w := tabwriter.NewWriter(r.out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PART\tTYPE\tCONTENT\tSTORED\tDATA")
		for _, p := range m.Parts {
			content := ""
			switch p.Type {
			case fmw.TypeDatabase:
				content = fmt.Sprintf("%s #%d, %s", clean(p.Table), p.Chunk, plural(p.Rows, "row", "rows"))
			default:
				content = plural(p.Entries, "entry", "entries")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", fmw.PlainName(p), p.Type, content, size(p.Bytes), size(p.BytesRaw))
		}
		w.Flush()
		return ExitOK
	}

	var total int64
	for _, p := range m.Parts {
		if p.Type != fmw.TypeDatabase {
			total += 2 * p.Bytes
		}
	}
	bar := newProgress(r.err, r.progressOn(), "Reading", total)
	enc := json.NewEncoder(r.out)
	enc.SetEscapeHTML(false)
	count := int64(0)
	err = a.ListFiles("", paths, bar.add, func(f fmw.FileInfo) {
		count++
		switch {
		case *asJSON:
			enc.Encode(f) //nolint:errcheck // Output errors show up at exit.
		case *long:
			name := clean(f.Path)
			if f.Type == "symlink" {
				name += " -> " + clean(f.Link)
			}
			if f.Type == "dir" {
				name += "/"
			}
			fmt.Fprintf(r.out, "%-7s %s %10s  %s  %s\n", f.Type, f.Mode, size(f.Size), f.ModTime.UTC().Format("2006-01-02 15:04"), name)
		default:
			fmt.Fprintln(r.out, clean(f.Path))
		}
	})
	bar.finish()
	if err != nil {
		return r.fail(err)
	}
	if count == 0 && len(paths) > 0 {
		fmt.Fprintln(r.err, "Nothing in the backup matches the given paths.")
		return ExitProblem
	}
	return ExitOK
}

func (r *runner) extract(args []string) int {
	fs := r.flags("extract", "[options] <archive.fmw> <folder>", `Unpacks a backup into a folder laid out like a WordPress root:
  <folder>/wp-content/...          the files (plugins, themes, uploads, ...)
  <folder>/database/*.sql.gz       the database, one file per table chunk, in restore order
  <folder>/fmw-manifest.json       what the backup holds (URLs, versions, checksums)
Every part is checked before it is used. Paths are kept inside the folder.`)
	var only listFlag
	fs.Var(&only, "only", "what to extract: files, database, root (comma separated; default all)")
	var paths listFlag
	fs.Var(&paths, "path", "only files under this wp-content path, for example uploads/2025/01 (repeatable)")
	sql := fs.String("sql", "gz", "database files: gz (as stored) or plain (.sql)")
	noLinks := fs.Bool("no-symlinks", false, "skip symbolic links")
	force := fs.Bool("force", false, "extract into a folder that is not empty (files from the backup replace existing ones)")
	noSpace := fs.Bool("skip-space-check", false, "do not compare the size of the data with the free disk space first")
	pos, code := r.parse(fs, args, 2, 2)
	if code >= 0 {
		return code
	}
	o := fmw.ExtractOptions{Dest: pos[1], Symlinks: !*noLinks, Force: *force, SkipSpaceCheck: *noSpace, Paths: paths, Warn: r.warn}
	switch *sql {
	case "gz":
	case "plain":
		o.PlainSQL = true
	default:
		fmt.Fprintln(r.err, "fmw-tools: --sql must be gz or plain")
		return ExitUsage
	}
	if len(only) == 0 {
		o.Files, o.Database, o.Root = true, true, true
	}
	for _, what := range only {
		switch what {
		case "files":
			o.Files = true
		case "database", "db":
			o.Database = true
		case "root":
			o.Root = true
		default:
			fmt.Fprintf(r.err, "fmw-tools: unknown --only value %q (files, database, root)\n", what)
			return ExitUsage
		}
	}
	if len(paths) > 0 && len(only) == 0 {
		o.Database, o.Root = false, false // --path picks files.
	}

	if items, err := os.ReadDir(o.Dest); err == nil && len(items) > 0 && !o.Force {
		fmt.Fprintf(r.err, "fmw-tools: %s is not empty; choose an empty folder or pass --force\n", o.Dest)
		return ExitUsage
	}
	a, m, err := r.open(pos[0], false)
	if err != nil {
		return r.fail(err)
	}
	defer a.Close()
	bar := newProgress(r.err, r.progressOn(), "Extracting", fmw.ExtractTotal(m, o))
	o.Progress = bar.add
	started := time.Now()
	st, err := a.Extract("", o)
	bar.finish()
	if err != nil {
		return r.fail(err)
	}
	var what []string
	for _, c := range []struct {
		n         int64
		one, many string
	}{{st.Files, "file", "files"}, {st.Dirs, "folder", "folders"}, {st.Symlinks, "symbolic link", "symbolic links"}, {st.SQLFiles, "database file", "database files"}} {
		if c.n > 0 {
			what = append(what, plural(c.n, c.one, c.many))
		}
	}
	if len(what) == 0 {
		what = []string{"nothing"}
	}
	fmt.Fprintf(r.out, "Extracted %s (%s) into %s in %s.\n", listing(what), size(st.Bytes), pos[1], time.Since(started).Round(time.Second))
	if st.Skipped > 0 {
		fmt.Fprintf(r.out, "Skipped %s (see the warnings above).\n", plural(st.Skipped, "entry", "entries"))
	}
	if st.SQLFiles > 0 {
		dbDir := filepath.Join(pos[1], "database")
		fmt.Fprintf(r.out, "\nImport the database in file name order, for example:\n")
		if o.PlainSQL {
			fmt.Fprintf(r.out, "  cat %s/*.sql | mysql -u USER -p DB_NAME\n", dbDir)
		} else {
			fmt.Fprintf(r.out, "  for f in %s/*.sql.gz; do gunzip -c \"$f\"; done | mysql -u USER -p DB_NAME\n", dbDir)
		}
		fmt.Fprintf(r.out, "Tables use the prefix %q. The site address was %s; replace it if the domain changes (wp search-replace).\n", clean(m.Site.TablePrefix), clean(m.Site.HomeURL))
	}
	return ExitOK
}

func (r *runner) decrypt(args []string) int {
	fs := r.flags("decrypt", "[options] <archive.fmw> [<output.fmw>]", "Writes an unencrypted copy of a password-protected backup, restorable without a password\n(by the plugin, or by hand with tar, gzip and mysql). Every part is authenticated first.\nThe default output is <domain>-<date>-<time>-<token>.fmw next to the backup.")
	force := fs.Bool("force", false, "replace the output file if it exists")
	pos, code := r.parse(fs, args, 1, 2)
	if code >= 0 {
		return code
	}
	a, m, err := r.open(pos[0], false)
	if err != nil {
		return r.fail(err)
	}
	defer a.Close()
	if !a.Encrypted() {
		fmt.Fprintln(r.err, "fmw-tools: this backup is not encrypted; there is nothing to decrypt")
		return ExitUsage
	}
	out := fmw.DecryptedName(pos[0], m)
	if len(pos) == 2 {
		out = pos[1]
	}
	if _, err := os.Stat(out); err == nil && !*force {
		fmt.Fprintf(r.err, "fmw-tools: %s exists; pass --force to replace it\n", out)
		return ExitUsage
	}
	bar := newProgress(r.err, r.progressOn(), "Decrypting", fmw.DecryptTotal(m))
	err = a.Decrypt("", out, bar.add)
	bar.finish()
	if err != nil {
		return r.fail(err)
	}
	stored := ""
	if info, err := os.Stat(out); err == nil {
		stored = " (" + size(info.Size()) + ")"
	}
	fmt.Fprintf(r.out, "Wrote %s%s. It has no password: store and share it with care.\n", out, stored)
	return ExitOK
}

func when(created string) string {
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return created
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func prefixed(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
}

func prefixAll(prefix string, items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, prefix+s)
	}
	return out
}

// listing joins "a", "b" and "c" as "a, b and c".
func listing(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
