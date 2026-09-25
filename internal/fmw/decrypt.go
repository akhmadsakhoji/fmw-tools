// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Generator names this program in files it writes (set by the command line).
var Generator = "fmw-tools"

// DecryptTotal is the number of bytes Decrypt reads (each part twice).
func DecryptTotal(m *Manifest) int64 {
	var total int64
	for _, p := range m.Parts {
		total += 2 * p.Bytes
	}
	return total
}

var encryptedName = regexp.MustCompile(`^backup-(\d{8}-\d{6}-[0-9a-f]{6})\.fmw$`)
var hostChars = regexp.MustCompile(`[^a-z0-9.-]`)

// DecryptedName suggests the file name of the decrypted copy: the plugin's
// usual <domain>-<date>-<time>-<token>.fmw, next to the encrypted backup.
func DecryptedName(archivePath string, m *Manifest) string {
	archivePath = filepath.Clean(archivePath)
	dir, base := filepath.Split(archivePath)
	host := ""
	if u, err := url.Parse(m.Site.HomeURL); err == nil {
		host = strings.Trim(hostChars.ReplaceAllString(strings.ToLower(u.Hostname()), "-"), ".-")
	}
	stem := strings.TrimSuffix(base, ".fmw")
	if mm := encryptedName.FindStringSubmatch(stem + ".fmw"); mm != nil && host != "" {
		return filepath.Join(dir, host+"-"+mm[1]+".fmw")
	}
	return filepath.Join(dir, stem+"-decrypted.fmw")
}

// sameOrInside tells whether out is the archive itself or lies inside a directory-mode archive.
func sameOrInside(archive, out string) bool {
	ai, err := os.Stat(archive)
	if err != nil {
		return false
	}
	if oi, err := os.Stat(out); err == nil && os.SameFile(ai, oi) {
		return true
	}
	if !ai.IsDir() {
		return false
	}
	absA, err1 := filepath.Abs(archive)
	absO, err2 := filepath.Abs(out)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(absA, absO)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Decrypt writes an unencrypted copy of an encrypted archive: standard
// format v1 without a password, restorable by the plugin and by hand with
// tar, gzip and mysql. Every part is authenticated (SHA-256 and HMAC)
// before it is decrypted, and decrypted sizes must match the manifest.
// The copy is written to out+".partial" and renamed when complete.
func (a *Archive) Decrypt(password, out string, progress func(int64)) error {
	if !a.Encrypted() {
		return errors.New("this backup is not encrypted")
	}
	m, err := a.Manifest(password)
	if err != nil {
		return err
	}
	if sameOrInside(a.Path, out) || sameOrInside(a.Path, out+".partial") {
		return errors.New("the decrypted copy cannot replace the backup or go inside it; choose another output file")
	}
	for _, p := range m.Parts {
		if p.BytesPlain <= 0 {
			return &UnsupportedError{Msg: fmt.Sprintf("part %s has no decrypted size in the manifest", p.Path)}
		}
	}
	created, err := time.Parse(time.RFC3339, a.Header.CreatedAt)
	if err != nil {
		created = time.Now()
	}
	created = created.UTC().Truncate(time.Second)

	header, err := parseObject(a.Header.raw)
	if err != nil {
		return &FormatError{Msg: "fmw.json cannot be rewritten: " + err.Error()}
	}
	header.del("kdf", "cipher", "manifest_hmac")
	if err := header.set("encrypted", false); err != nil {
		return err
	}
	if err := header.set("decrypted_by", Generator); err != nil {
		return err
	}
	manifest, err := parseObject(m.RawManifest())
	if err != nil {
		return &FormatError{Msg: "the manifest cannot be rewritten: " + err.Error()}
	}
	partsRaw, _ := manifest.get("parts")
	var parts []json.RawMessage
	if err := json.Unmarshal(partsRaw, &parts); err != nil || len(parts) != len(m.Parts) {
		return &FormatError{Msg: "the manifest's part list cannot be rewritten"}
	}

	partial := out + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(partial)
		}
	}()
	tw := tar.NewWriter(f)
	if err := writeJSON(tw, "fmw.json", header, created); err != nil {
		return err
	}

	a.PrepareKeys(m.Parts)
	var archived int64
	for i, p := range m.Parts {
		if err := a.CheckPart(p, progress); err != nil {
			return err
		}
		name := PlainName(p)
		if err := tw.WriteHeader(entryHeader(name, p.BytesPlain, created)); err != nil {
			return err
		}
		r, err := a.OpenDecrypted(p, progress)
		if err != nil {
			return err
		}
		sum := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, sum), r)
		r.Close()
		if err != nil {
			if errors.Is(err, tar.ErrWriteTooLong) {
				return &PartError{Part: p.Path, Msg: "decrypts to more bytes than the manifest says"}
			}
			return fmt.Errorf("part %s: %w", p.Path, err)
		}
		if n != p.BytesPlain {
			return &PartError{Part: p.Path, Msg: fmt.Sprintf("decrypts to %d bytes; the manifest says %d", n, p.BytesPlain)}
		}
		archived += n

		rec, err := parseObject(parts[i])
		if err != nil {
			return &FormatError{Msg: "a part record cannot be rewritten"}
		}
		rec.del("hmac", "bytes_plain")
		for _, kv := range []struct {
			k string
			v any
		}{{"path", name}, {"bytes", n}, {"sha256", hex.EncodeToString(sum.Sum(nil))}} {
			if err := rec.set(kv.k, kv.v); err != nil {
				return err
			}
		}
		if parts[i], err = rec.MarshalJSON(); err != nil {
			return err
		}
	}

	if err := manifest.set("parts", parts); err != nil {
		return err
	}
	if err := setNested(&manifest, "options", "encrypted", false); err != nil {
		return err
	}
	if err := setNested(&manifest, "totals", "bytes_archived", archived); err != nil {
		return err
	}
	if err := writeJSON(tw, "manifest.json", manifest, created); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(partial, out); err != nil {
		return err
	}
	ok = true
	return nil
}

func setNested(o *object, key, sub string, v any) error {
	raw, ok := o.get(key)
	if !ok {
		return nil
	}
	inner, err := parseObject(raw)
	if err != nil {
		return nil // Not an object: leave it as it is.
	}
	if err := inner.set(sub, v); err != nil {
		return err
	}
	b, err := inner.MarshalJSON()
	if err != nil {
		return err
	}
	return o.set(key, json.RawMessage(b))
}

func entryHeader(name string, size int64, mtime time.Time) *tar.Header {
	return &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     0o644,
		ModTime:  mtime,
		Format:   tar.FormatUnknown, // ustar, or PAX only when a value needs it (format v1, section 2).
	}
}

func writeJSON(tw *tar.Writer, name string, o object, mtime time.Time) error {
	raw, err := o.MarshalJSON()
	if err != nil {
		return err
	}
	pretty, err := IndentJSON(raw)
	if err != nil {
		return err
	}
	// Like the plugin: four-space indent and a final newline.
	if err := tw.WriteHeader(entryHeader(name, int64(len(pretty)), mtime)); err != nil {
		return err
	}
	_, err = tw.Write(pretty)
	return err
}
