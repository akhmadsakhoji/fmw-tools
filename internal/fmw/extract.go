// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ExtractOptions says what Extract writes where.
type ExtractOptions struct {
	Dest           string
	Files          bool        // wp-content from file parts.
	Database       bool        // SQL files from database parts.
	Root           bool        // WordPress root files (root-files parts).
	PlainSQL       bool        // Decompress the SQL (default: keep .sql.gz).
	Paths          []string    // Only these wp-content paths (a file, or a folder and everything in it).
	Symlinks       bool        // Create symbolic links (otherwise they are skipped).
	Force          bool        // Allow a folder that is not empty; files from the archive replace existing ones.
	SkipSpaceCheck bool        // Do not compare the data size with the free disk space first.
	Site           *SiteFilter // Only one site of a network backup (its tables and media, users, shared files).
	Progress       func(int64)
	Warn           func(string)
}

// ExtractStats counts what Extract wrote.
type ExtractStats struct {
	Files      int64  `json:"files"`
	Dirs       int64  `json:"dirs"`
	Symlinks   int64  `json:"symlinks"`
	Skipped    int64  `json:"skipped"`
	Bytes      int64  `json:"bytes"`
	SQLFiles   int64  `json:"sql_files"`
	ContentDir string `json:"content_dir"`
}

// SelectParts returns the parts Extract reads for these options.
func SelectParts(m *Manifest, o ExtractOptions) []Part {
	var out []Part
	for _, p := range m.Parts {
		if o.Site != nil && p.Type == TypeDatabase && !o.Site.WantTable(p.Table) {
			continue // Another site's table, the network's, or its views and triggers.
		}
		if (p.Type == TypeFiles && o.Files) || (p.Type == TypeDatabase && o.Database) || (p.Type == TypeRootFiles && o.Root) {
			out = append(out, p)
		}
	}
	return out
}

// ExtractTotal is the number of bytes Extract reads (each part twice: check, then unpack).
func ExtractTotal(m *Manifest, o ExtractOptions) int64 {
	var total int64
	for _, p := range SelectParts(m, o) {
		total += 2 * p.Bytes
	}
	return total
}

// ExtractNeeds is the disk space Extract writes, from the sizes in the manifest.
func ExtractNeeds(m *Manifest, o ExtractOptions) int64 {
	var total int64
	for _, p := range SelectParts(m, o) {
		switch {
		case p.Type != TypeDatabase, o.PlainSQL:
			total = addSat(total, p.BytesRaw)
		case p.Encrypted():
			total = addSat(total, p.BytesPlain)
		default:
			total = addSat(total, p.Bytes)
		}
	}
	return total
}

// addSat adds sizes without overflowing (manifest values are untrusted).
func addSat(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// ContentDir is the wp-content folder name to extract into.
func ContentDir(m *Manifest) string {
	rel, err := SafeRelative(m.Site.ContentDir)
	if err != nil || rel == "" || (runtime.GOOS == "windows" && WindowsProblem(rel) != "") {
		return "wp-content"
	}
	return rel
}

// maxPendingLinks bounds the memory links take until they are created.
const maxPendingLinks = 64 << 20

// Extract unpacks the backup into a folder laid out like a WordPress root:
// <content_dir>/... for files, database/*.sql(.gz) for the database, and
// fmw-manifest.json. Each part is checked (size, SHA-256, HMAC) before any of
// its content is used, and checked again while it is used. Paths are
// confined to the folder: absolute paths and ".." are refused, links are
// created last and only when they stay inside, and nothing is written
// through a link.
func (a *Archive) Extract(password string, o ExtractOptions) (*ExtractStats, error) {
	m, err := a.Manifest(password)
	if err != nil {
		return nil, err
	}
	if o.Warn == nil {
		o.Warn = func(string) {}
	}
	var filters []string
	for _, p := range o.Paths {
		rel, err := SafeRelative(p)
		if err != nil {
			return nil, err
		}
		if rel != "" {
			filters = append(filters, rel)
		}
	}

	t, err := newTree(o.Dest, o.Force)
	if err != nil {
		return nil, err
	}
	// The sizes come from the manifest, and extraction stops if a part holds more.
	if need := ExtractNeeds(m, o); !o.SkipSpaceCheck && len(filters) == 0 && o.Site == nil { // One site needs less than its parts hold.
		if free := freeSpace(t.root); free >= 0 && (need > free || free-need < need/20) {
			return nil, fmt.Errorf("not enough disk space in %s: the backup needs about %d MB, %d MB are free (--skip-space-check to try anyway)", o.Dest, need>>20, free>>20)
		}
	}
	st := &ExtractStats{ContentDir: ContentDir(m)}
	if raw := m.RawManifest(); raw != nil {
		pretty, err := IndentJSON(raw)
		if err != nil {
			return nil, err
		}
		if err := t.writeFile("fmw-manifest.json", bytes.NewReader(pretty), int64(len(pretty)), 0o600, time.Now()); err != nil {
			return nil, err
		}
	}

	parts := a.inArchiveOrder(SelectParts(m, o))
	a.PrepareKeys(parts)
	links := &linkList{}
	matched := len(filters) == 0
	for _, p := range parts {
		if err := a.CheckPart(p, o.Progress); err != nil {
			return st, err
		}
		switch p.Type {
		case TypeDatabase:
			if err := a.extractSQL(t, p, o, st); err != nil {
				return st, err
			}
		default:
			base := st.ContentDir
			var only []string
			if p.Type == TypeRootFiles {
				base = ""
			} else {
				only = filters
			}
			found, err := a.extractTar(t, p, base, only, o, st, links, p.Type == TypeFiles)
			if err != nil {
				return st, err
			}
			matched = matched || found
		}
	}
	if !matched {
		o.Warn("nothing in the backup matched the given paths")
	}
	t.createLinks(links.items, o, st)
	t.finishDirs()
	return st, nil
}

func (a *Archive) extractSQL(t *tree, p Part, o ExtractOptions, st *ExtractStats) error {
	name := path.Base(PlainName(p))
	if runtime.GOOS == "windows" && WindowsProblem(name) != "" {
		return &PartError{Part: p.Path, Msg: "has a name Windows cannot store"}
	}
	r, err := a.OpenDecrypted(p, o.Progress)
	if err != nil {
		return err
	}
	defer r.Close()
	var src io.Reader = r
	limit := int64(-1)
	if o.PlainSQL && p.Compression == "gzip" {
		z, err := gzip.NewReader(r)
		if err != nil {
			return &PartError{Part: p.Path, Msg: fmt.Sprintf("is not valid gzip: %v", err)}
		}
		defer z.Close()
		limit = p.BytesRaw
		src = io.LimitReader(z, limit+1) // A gzip bomb stops at the size the manifest records.
		name = strings.TrimSuffix(name, ".gz")
	}
	n, err := t.writeStream("database/"+name, src, 0o600, time.Now())
	if err != nil {
		return fmt.Errorf("part %s: %w", p.Path, err)
	}
	if limit >= 0 && n > limit {
		return &PartError{Part: p.Path, Msg: fmt.Sprintf("holds more data than the %d bytes the manifest records", limit)}
	}
	if err := drain(r); err != nil { // Confirms the part did not change while it was read.
		return err
	}
	st.SQLFiles++
	st.Bytes += n
	return nil
}

type pendingLink struct {
	rel, target string
}

type linkList struct {
	items []pendingLink
	bytes int
}

// rootAllowed is the allowlist of WordPress root files (format v1, section 5).
var rootAllowed = regexp.MustCompile(`^(\.htaccess|robots\.txt|ads\.txt|google[^/]*\.html|BingSiteAuth\.xml)$`)

func (a *Archive) extractTar(t *tree, p Part, base string, only []string, o ExtractOptions, st *ExtractStats, links *linkList, content bool) (bool, error) {
	r, err := a.OpenPlain(p, o.Progress)
	if err != nil {
		return false, err
	}
	defer r.Close()
	found := false
	guard := &entryGuard{part: p}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return found, &PartError{Part: p.Path, Msg: fmt.Sprintf("has a damaged TAR stream: %v", err)}
		}
		rel, err := guard.check(h)
		if err != nil {
			return found, err
		}
		if rel == "" || !wanted(rel, only) || (content && o.Site != nil && !o.Site.WantFile(rel)) {
			continue
		}
		found = true
		if p.Type == TypeRootFiles && (!rootAllowed.MatchString(rel) || h.Typeflag != tar.TypeReg) {
			o.Warn(fmt.Sprintf("skipped %s: only .htaccess, robots.txt, ads.txt, google*.html and BingSiteAuth.xml are restored to the WordPress root", printable(rel)))
			st.Skipped++
			continue
		}
		target := rel
		if base != "" {
			target = base + "/" + rel
		}
		if runtime.GOOS == "windows" {
			if why := WindowsProblem(rel); why != "" {
				o.Warn(fmt.Sprintf("skipped %s: the name %s", printable(rel), why))
				st.Skipped++
				continue
			}
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := t.mkdirAll(target); err != nil {
				return found, err
			}
			t.dirs[target] = dirMeta{mode: fs.FileMode(h.Mode).Perm(), mtime: h.ModTime}
			st.Dirs++
		case tar.TypeReg, tar.TypeRegA:
			n, err := t.writeStream(target, io.LimitReader(tr, h.Size), fs.FileMode(h.Mode).Perm(), h.ModTime)
			if err != nil {
				return found, err
			}
			if n != h.Size {
				return found, &PartError{Part: p.Path, Msg: fmt.Sprintf("ends inside %s", printable(rel))}
			}
			st.Files++
			st.Bytes += n
		case tar.TypeSymlink:
			if !o.Symlinks {
				st.Skipped++
				continue
			}
			if _, err := SymlinkTarget(target, h.Linkname); err != nil {
				o.Warn("skipped " + err.Error())
				st.Skipped++
				continue
			}
			links.bytes += len(target) + len(h.Linkname)
			if links.bytes > maxPendingLinks {
				return found, &PartError{Part: p.Path, Msg: "holds an unreasonable number of links"}
			}
			links.items = append(links.items, pendingLink{rel: target, target: h.Linkname})
		default:
			o.Warn(fmt.Sprintf("skipped %s: entry type %q is not extracted", printable(rel), string(h.Typeflag)))
			st.Skipped++
		}
	}
	return found, drain(r)
}

// drain reads a part stream to its end, where its SHA-256 is compared again.
func drain(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// wanted applies the --path filters: the path itself and what is inside it
// (the folders leading to it are created as needed).
func wanted(rel string, only []string) bool {
	if len(only) == 0 {
		return true
	}
	for _, f := range only {
		if rel == f || strings.HasPrefix(rel, f+"/") {
			return true
		}
	}
	return false
}

type dirMeta struct {
	mode  fs.FileMode
	mtime time.Time
}

// tree writes inside one root folder and never follows a symbolic link.
type tree struct {
	root string
	real map[string]bool // Folders known to be real (not links) under root.
	dirs map[string]dirMeta
}

func newTree(dest string, force bool) (*tree, error) {
	if dest == "" {
		return nil, errors.New("no destination folder given")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	items, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 && !force {
		return nil, fmt.Errorf("%s is not empty; choose an empty folder or pass --force", dest)
	}
	return &tree{root: root, real: map[string]bool{"": true}, dirs: map[string]dirMeta{}}, nil
}

func (t *tree) abs(rel string) string { return filepath.Join(t.root, filepath.FromSlash(rel)) }

// mkdirAll creates the folders of rel one by one, refusing any that is a link or a file.
func (t *tree) mkdirAll(rel string) error {
	if t.real[rel] {
		return nil
	}
	for end := 0; end < len(rel); {
		// Prefixes are slices of rel: the map keys share its memory.
		next := strings.IndexByte(rel[end+1:], '/')
		if next < 0 {
			end = len(rel)
		} else {
			end += 1 + next
		}
		cur := rel[:end]
		if t.real[cur] {
			continue
		}
		info, err := os.Lstat(t.abs(cur))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(t.abs(cur), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			if info, err = os.Lstat(t.abs(cur)); err != nil {
				return err
			}
			if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
				return fmt.Errorf("%s changed while extracting", printable(cur))
			}
		case err != nil:
			return err
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("refusing to write through the symbolic link %s", printable(cur))
		case !info.IsDir():
			return fmt.Errorf("%s exists and is not a folder", printable(cur))
		}
		t.real[cur] = true
	}
	return nil
}

func (t *tree) parent(rel string) error {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return t.mkdirAll(rel[:i])
	}
	return nil
}

// clear removes a file or link in the way of a new entry (never a folder).
func (t *tree) clear(rel string) error {
	info, err := os.Lstat(t.abs(rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s exists as a folder", printable(rel))
	}
	return os.Remove(t.abs(rel))
}

// writeStream writes a new file (O_EXCL: never through an existing link).
func (t *tree) writeStream(rel string, r io.Reader, mode fs.FileMode, mtime time.Time) (int64, error) {
	if err := t.parent(rel); err != nil {
		return 0, err
	}
	if err := t.clear(rel); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(t.abs(rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if mode == 0 {
		mode = 0o644
	}
	if err == nil {
		err = f.Chmod((mode | 0o400) &^ 0o022) // Like a umask of 022: nobody else may write.
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if !mtime.IsZero() {
		_ = os.Chtimes(t.abs(rel), mtime, mtime)
	}
	return n, nil
}

func (t *tree) writeFile(rel string, r io.Reader, size int64, mode fs.FileMode, mtime time.Time) error {
	n, err := t.writeStream(rel, r, mode, mtime)
	if err == nil && n != size {
		err = fmt.Errorf("%s: wrote %d of %d bytes", rel, n, size)
	}
	return err
}

// createLinks makes the symbolic links once every file and folder exists.
// Targets were checked when the links were read (SymlinkTarget: relative,
// inside the folder, ".." only at the start), and each link's folder is a
// real folder, so no chain of links from the archive can lead outside.
// Links that were already in the folder (--force) were never checked, so a
// target may not pass through any link that exists on disk.
func (t *tree) createLinks(links []pendingLink, o ExtractOptions, st *ExtractStats) {
	for _, l := range links {
		err := t.parent(l.rel)
		if err == nil {
			err = t.throughLink(l)
		}
		if err == nil {
			err = t.clear(l.rel)
		}
		if err == nil {
			err = os.Symlink(filepath.FromSlash(l.target), t.abs(l.rel))
		}
		if err != nil {
			o.Warn(fmt.Sprintf("skipped link %s: %v", printable(l.rel), err))
			st.Skipped++
			continue
		}
		st.Symlinks++
	}
}

// finishDirs applies folder permissions and times, deepest first (writing into a folder changes its time).
func (t *tree) finishDirs() {
	names := make([]string, 0, len(t.dirs))
	for n := range t.dirs {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return strings.Count(names[i], "/") > strings.Count(names[j], "/") })
	for _, n := range names {
		d := t.dirs[n]
		if info, err := os.Lstat(t.abs(n)); err != nil || !info.IsDir() {
			continue
		}
		_ = os.Chmod(t.abs(n), (d.mode|0o700)&^0o022)
		if !d.mtime.IsZero() {
			_ = os.Chtimes(t.abs(n), d.mtime, d.mtime)
		}
	}
}

// IndentJSON pretty-prints JSON with four spaces, like the plugin.
func IndentJSON(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "    "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// throughLink refuses a target whose path passes through an existing link.
func (t *tree) throughLink(l pendingLink) error {
	resolved, err := SymlinkTarget(l.rel, l.target)
	if err != nil {
		return err
	}
	for i := 0; i < len(resolved); i++ {
		if resolved[i] != '/' {
			continue
		}
		if info, err := os.Lstat(t.abs(resolved[:i])); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return errors.New("its target passes through an existing link")
		}
	}
	return nil
}
