// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// SupportedVersion is the newest archive format version this package reads.
const SupportedVersion = 1

const maxJSON = 16 << 20

// Header is fmw.json, the first entry of every archive.
type Header struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Generator string `json:"generator"`
	Encrypted bool   `json:"encrypted"`
	KDF       struct {
		Algorithm  string `json:"algorithm"`
		Iterations int    `json:"iterations"`
	} `json:"kdf"`
	Cipher       string `json:"cipher"`
	ManifestHMAC string `json:"manifest_hmac"`

	raw []byte
}

// Manifest is manifest.json: what the backup holds and the checksums of its parts.
type Manifest struct {
	Format    string  `json:"format"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"`
	Generator string  `json:"generator"`
	Site      Site    `json:"site"`
	Options   Options `json:"options"`
	Totals    Totals  `json:"totals"`
	Parts     []Part  `json:"parts"`

	raw []byte
}

// Site describes the source site.
type Site struct {
	HomeURL     string `json:"home_url"`
	SiteURL     string `json:"site_url"`
	Abspath     string `json:"abspath"`
	ContentDir  string `json:"content_dir"`
	UploadsDir  string `json:"uploads_dir"`
	TablePrefix string `json:"table_prefix"`
	Multisite   bool   `json:"multisite"`
	Sites       []struct {
		BlogID    json.Number     `json:"blog_id"`
		Domain    string          `json:"domain"`
		Path      string          `json:"path"`
		NetworkID json.RawMessage `json:"network_id"`
	} `json:"sites"`
	Network    json.RawMessage `json:"network"` // Networks only, read loosely by Manifest.Network: a bad value never fails the manifest.
	WPVersion  string          `json:"wp_version"`
	PHPVersion string          `json:"php_version"`
	DB         struct {
		Engine  string `json:"engine"`
		Version string `json:"version"`
		Charset string `json:"charset"`
		Collate string `json:"collate"`
	} `json:"db"`
	ActivePlugins []string `json:"active_plugins"`
	Template      string   `json:"template"`
	Stylesheet    string   `json:"stylesheet"`
}

// Options records what was deliberately left out of the backup.
type Options struct {
	Exclude          []string `json:"exclude"`
	ExcludeTables    []string `json:"exclude_tables"`
	ExcludePaths     []string `json:"exclude_paths"`
	IncludeRootFiles bool     `json:"include_root_files"`
	PartSize         int64    `json:"part_size"`
	Encrypted        bool     `json:"encrypted"`
}

// Totals are the sums used for progress and disk space checks.
type Totals struct {
	Files         int64 `json:"files"`
	Tables        int64 `json:"tables"`
	Rows          int64 `json:"rows"`
	BytesRaw      int64 `json:"bytes_raw"`
	BytesArchived int64 `json:"bytes_archived"`
}

// Part types.
const (
	TypeDatabase  = "database"
	TypeFiles     = "files"
	TypeRootFiles = "root-files"
)

// Part is one entry of manifest.parts.
type Part struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Table       string `json:"table,omitempty"`
	Chunk       int    `json:"chunk,omitempty"`
	Rows        int64  `json:"rows,omitempty"`
	Entries     int64  `json:"entries,omitempty"`
	Compression string `json:"compression"`
	BytesRaw    int64  `json:"bytes_raw"`
	Bytes       int64  `json:"bytes"`
	BytesPlain  int64  `json:"bytes_plain,omitempty"`
	SHA256      string `json:"sha256"`
	HMAC        string `json:"hmac,omitempty"`
}

// Encrypted tells whether the part is stored encrypted.
func (p Part) Encrypted() bool { return strings.HasSuffix(p.Path, ".enc") }

// Archive is an opened .fmw backup.
type Archive struct {
	Path      string
	Header    Header
	container *Container
	manifest  *Manifest
	password  string
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Open reads fmw.json and checks that this version can read the archive.
func Open(path string) (*Archive, error) {
	c, err := OpenContainer(path)
	if err != nil {
		return nil, err
	}
	a := &Archive{Path: path, container: c}
	if err := a.readHeader(); err != nil {
		c.Close()
		return nil, err
	}
	return a, nil
}

// Close releases the archive.
func (a *Archive) Close() error { return a.container.Close() }

// Container gives access to the raw entries.
func (a *Archive) Container() *Container { return a.container }

func (a *Archive) readHeader() error {
	entries := a.container.Entries()
	if !a.container.Dir() && (len(entries) == 0 || entries[0].Name != "fmw.json") {
		return fmt.Errorf("%w (fmw.json is not the first entry)", ErrNotFMW)
	}
	data, err := a.container.ReadSmall("fmw.json", maxJSON)
	if err != nil {
		return err
	}
	var h Header
	if err := json.Unmarshal(data, &h); err != nil {
		return fmt.Errorf("%w (fmw.json is not valid: %v)", ErrNotFMW, err)
	}
	if h.Format != "fmw" {
		return fmt.Errorf("%w (unknown format %q)", ErrNotFMW, printable(h.Format))
	}
	if h.Version < 1 {
		return &FormatError{Msg: "fmw.json has no valid format version"}
	}
	if h.Version > SupportedVersion {
		return &UnsupportedError{Msg: fmt.Sprintf("archive format version %d is newer than this FMW Tools supports (%d); update FMW Tools", h.Version, SupportedVersion)}
	}
	if h.Encrypted {
		if h.KDF.Algorithm != "pbkdf2-sha256" || h.Cipher != "aes-256-cbc" {
			return &UnsupportedError{Msg: fmt.Sprintf("unsupported encryption (%s, %s); update FMW Tools", printable(h.KDF.Algorithm), printable(h.Cipher))}
		}
		if h.KDF.Iterations < MinIterations || h.KDF.Iterations > MaxIterations {
			return &FormatError{Msg: "unreasonable key derivation settings in fmw.json"}
		}
		if !hex64.MatchString(h.ManifestHMAC) || h.ManifestHMAC == strings.Repeat("0", 64) {
			return &FormatError{Msg: "the archive is incomplete: fmw.json has no manifest HMAC (the backup did not finish)"}
		}
	}
	h.raw = data
	a.Header = h
	return nil
}

// RawHeader returns fmw.json as stored.
func (a *Archive) RawHeader() []byte { return a.Header.raw }

// Encrypted tells whether a password is needed for the manifest and the parts.
func (a *Archive) Encrypted() bool { return a.Header.Encrypted }

// ManifestName is the entry holding the manifest.
func (a *Archive) ManifestName() string {
	if a.Encrypted() {
		return "manifest.json.enc"
	}
	return "manifest.json"
}

// Manifest reads (and for encrypted backups authenticates and decrypts) the
// manifest, then checks every part record. The password is remembered for
// the parts; once the manifest is read, "" returns it again.
func (a *Archive) Manifest(password string) (*Manifest, error) {
	if a.manifest != nil && (!a.Encrypted() || password == "" || password == a.password) {
		return a.manifest, nil
	}
	if a.Encrypted() && password == "" {
		return nil, ErrPasswordRequired
	}
	data, err := a.container.ReadSmall(a.ManifestName(), maxJSON)
	if err != nil {
		var fe *FormatError
		if errors.Is(err, ErrNotFMW) || errors.As(err, &fe) {
			return nil, &FormatError{Msg: fmt.Sprintf("the archive has no readable %s; it may be incomplete", a.ManifestName())}
		}
		return nil, err
	}
	if a.Encrypted() {
		want, _ := hex.DecodeString(a.Header.ManifestHMAC)
		data, err = DecryptSmall(data, password, a.Header.KDF.Iterations, want)
		if err != nil {
			if errors.Is(err, ErrBadPadding) {
				return nil, &FormatError{Msg: "the manifest is damaged although its HMAC matched"}
			}
			return nil, err
		}
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &FormatError{Msg: fmt.Sprintf("the manifest is not valid JSON: %v", err)}
	}
	if m.Version > SupportedVersion {
		return nil, &UnsupportedError{Msg: fmt.Sprintf("manifest version %d is newer than this FMW Tools supports; update FMW Tools", m.Version)}
	}
	if m.Parts == nil {
		return nil, &FormatError{Msg: "the manifest has no part list"}
	}
	if err := checkParts(m.Parts, a.Encrypted()); err != nil {
		return nil, err
	}
	m.raw = data
	a.manifest = &m
	a.password = password
	return &m, nil
}

// RawManifest returns the manifest JSON as stored (after decryption).
func (m *Manifest) RawManifest() []byte { return m.raw }

var partName = regexp.MustCompile(`^(database|files|root-files)/[A-Za-z0-9._$-]+$`)

// checkParts applies the rules of format v1, sections 4 and 9: safe names,
// known types and compressions, checksums present, encryption consistent.
func checkParts(parts []Part, encrypted bool) error {
	seen := map[string]bool{}
	for _, p := range parts {
		if !partName.MatchString(p.Path) || strings.Contains(p.Path, "..") {
			return &FormatError{Msg: fmt.Sprintf("unsafe part name %q in the manifest; the archive is refused", printable(p.Path))}
		}
		if seen[p.Path] {
			return &FormatError{Msg: fmt.Sprintf("part %s is listed twice in the manifest", p.Path)}
		}
		seen[p.Path] = true
		switch p.Type {
		case TypeDatabase, TypeFiles, TypeRootFiles:
		default:
			return &UnsupportedError{Msg: fmt.Sprintf("unknown part type %q; update FMW Tools", printable(p.Type))}
		}
		if !strings.HasPrefix(p.Path, p.Type+"/") {
			return &FormatError{Msg: fmt.Sprintf("part %s is in the wrong folder for type %s", p.Path, p.Type)}
		}
		if p.Compression != "gzip" && p.Compression != "none" {
			return &UnsupportedError{Msg: fmt.Sprintf("unknown compression %q in part %s; update FMW Tools", printable(p.Compression), p.Path)}
		}
		if p.Encrypted() != encrypted {
			return &FormatError{Msg: fmt.Sprintf("part %s does not match the archive's encryption setting", p.Path)}
		}
		if !hex64.MatchString(p.SHA256) {
			return &FormatError{Msg: fmt.Sprintf("part %s has no valid SHA-256 in the manifest", p.Path)}
		}
		if encrypted && !hex64.MatchString(p.HMAC) {
			return &FormatError{Msg: fmt.Sprintf("part %s has no valid HMAC in the manifest", p.Path)}
		}
		if p.Bytes < 0 || p.BytesRaw < 0 || p.BytesPlain < 0 || (encrypted && p.Bytes < HeaderLen+blockSize) {
			return &FormatError{Msg: fmt.Sprintf("part %s has impossible sizes in the manifest", p.Path)}
		}
	}
	return nil
}

// tableFileName replaces every byte outside [A-Za-z0-9_$-] with "_", byte by
// byte like the plugin's preg_replace (so "café" gives "caf__").
func tableFileName(table string) string {
	b := []byte(table)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c == '-') {
			b[i] = '_'
		}
	}
	return string(b)
}

var encDBName = regexp.MustCompile(`^database/(\d{4})\.(\d{4})\.sql\.gz\.enc$`)

// PlainName is the part's name in an unencrypted archive: without ".enc",
// and database parts get their table name back (format v1, section 6).
func PlainName(p Part) string {
	if m := encDBName.FindStringSubmatch(p.Path); m != nil && p.Table != "" {
		return fmt.Sprintf("database/%s-%s.%s.sql.gz", m[1], tableFileName(p.Table), m[2])
	}
	return strings.TrimSuffix(p.Path, ".enc")
}

// CheckResult is what CheckPart found.
type CheckResult struct {
	Size   int64
	SHA256 string
	MAC    string // Hex; empty for unencrypted parts.
}

// CheckPart reads a stored part once and compares its size, SHA-256 and
// (encrypted parts) HMAC with the manifest. The manifest's SHA-256 is
// authenticated by the manifest HMAC, so a part that passes is genuine.
func (a *Archive) CheckPart(p Part, progress func(int64)) error {
	e, ok := a.container.Lookup(p.Path)
	if !ok {
		return &PartError{Part: p.Path, Msg: "is missing"}
	}
	r, err := a.container.Open(e)
	if err != nil {
		return err
	}
	defer r.Close()
	var mac hash.Hash
	if p.Encrypted() {
		head := make([]byte, HeaderLen)
		if _, err := io.ReadFull(r, head); err != nil {
			return &PartError{Part: p.Path, Msg: "is too short to be encrypted"}
		}
		salt, err := SaltOf(head)
		if err != nil {
			return &PartError{Part: p.Path, Msg: err.Error()}
		}
		k, err := DeriveKeys(a.password, salt, a.Header.KDF.Iterations)
		if err != nil {
			return err
		}
		mac = NewMAC(k)
		r = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), r), r} // The HMAC covers the whole stored file, header included.
	}
	sum := sha256.New()
	var w io.Writer = sum
	if mac != nil {
		w = io.MultiWriter(sum, mac)
	}
	n, err := copyProgress(w, r, progress)
	if err != nil {
		return err
	}
	if n != p.Bytes || e.Size != p.Bytes {
		return &PartError{Part: p.Path, Msg: fmt.Sprintf("is %d bytes; the manifest says %d", e.Size, p.Bytes)}
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(p.SHA256)) {
		return &PartError{Part: p.Path, Msg: "is corrupt (SHA-256 mismatch)"}
	}
	if mac != nil && !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(p.HMAC)) {
		return &PartError{Part: p.Path, Msg: "failed its HMAC check (tampered, or written with another password)"}
	}
	return nil
}

// PartError is a problem with one part.
type PartError struct {
	Part string
	Msg  string
}

func (e *PartError) Error() string { return "part " + e.Part + " " + e.Msg }

// OpenPlain returns the part's content: decrypted and decompressed (a TAR
// stream for file parts, SQL for database parts). Call CheckPart first:
// data must not be used before its checksum matched (format v1, section 7).
func (a *Archive) OpenPlain(p Part, progress func(int64)) (io.ReadCloser, error) {
	r, err := a.OpenDecrypted(p, progress)
	if err != nil {
		return nil, err
	}
	if p.Compression != "gzip" {
		return r, nil
	}
	z, err := gzip.NewReader(r)
	if err != nil {
		r.Close()
		return nil, &PartError{Part: p.Path, Msg: fmt.Sprintf("is not valid gzip: %v", err)}
	}
	return struct {
		io.Reader
		io.Closer
	}{z, closers{z, r}}, nil
}

// OpenDecrypted returns the part as stored before encryption (still
// compressed). For unencrypted archives that is the stored part itself.
func (a *Archive) OpenDecrypted(p Part, progress func(int64)) (io.ReadCloser, error) {
	e, ok := a.container.Lookup(p.Path)
	if !ok {
		return nil, &PartError{Part: p.Path, Msg: "is missing"}
	}
	stored, err := a.container.Open(e)
	if err != nil {
		return nil, err
	}
	// Hash again while reading: a part that changed after CheckPart (a synced
	// or shared folder) fails at its end instead of passing silently.
	var r io.ReadCloser = struct {
		io.Reader
		io.Closer
	}{&counter{r: &rehash{r: stored, h: sha256.New(), part: p}, progress: progress}, stored}
	if !p.Encrypted() {
		return r, nil
	}
	head := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, head); err != nil {
		r.Close()
		return nil, &PartError{Part: p.Path, Msg: "is too short to be encrypted"}
	}
	salt, err := SaltOf(head)
	if err != nil {
		r.Close()
		return nil, &PartError{Part: p.Path, Msg: err.Error()}
	}
	k, err := DeriveKeys(a.password, salt, a.Header.KDF.Iterations)
	if err != nil {
		r.Close()
		return nil, err
	}
	d, err := NewDecryptReader(r, k)
	if err != nil {
		r.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{d, r}, nil
}

type closers []io.Closer

func (c closers) Close() error {
	var first error
	for _, x := range c {
		if err := x.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// copyProgress copies in 1 MiB steps and reports each step.
func copyProgress(w io.Writer, r io.Reader, progress func(int64)) (int64, error) {
	buf := make([]byte, 1<<20)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if progress != nil {
				progress(int64(n))
			}
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// PrepareKeys derives the keys of encrypted parts in parallel, one worker
// per CPU core. Each part has its own salt and each derivation takes close
// to a second, so doing this up front saves minutes on large backups.
func (a *Archive) PrepareKeys(parts []Part) {
	if !a.Encrypted() || a.password == "" {
		return
	}
	var salts [][]byte
	for _, p := range parts {
		e, ok := a.container.Lookup(p.Path)
		if !ok || e.Size < HeaderLen {
			continue
		}
		r, err := a.container.Open(e)
		if err != nil {
			continue
		}
		head := make([]byte, HeaderLen)
		_, err = io.ReadFull(r, head)
		r.Close()
		if salt, serr := SaltOf(head); err == nil && serr == nil {
			salts = append(salts, salt)
		}
	}
	jobs := make(chan []byte)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for salt := range jobs {
				DeriveKeys(a.password, salt, a.Header.KDF.Iterations) //nolint:errcheck // Errors come back when the part is read.
			}
		}()
	}
	for _, s := range salts {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
}

// rehash computes the SHA-256 of a stream and compares it with the manifest at the end.
type rehash struct {
	r    io.Reader
	h    hash.Hash
	part Part
}

func (x *rehash) Read(b []byte) (int, error) {
	n, err := x.r.Read(b)
	x.h.Write(b[:n])
	if errors.Is(err, io.EOF) && hex.EncodeToString(x.h.Sum(nil)) != x.part.SHA256 {
		return n, &PartError{Part: x.part.Path, Msg: "changed while it was being read (SHA-256 mismatch)"}
	}
	return n, err
}
