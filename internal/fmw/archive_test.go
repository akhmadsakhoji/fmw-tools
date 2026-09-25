// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures written by the WordPress plugin (FMW 0.1.0-dev): a small site
// backed up twice in the same second, once without and once with a password.
const (
	plainFixture     = "../../testdata/plain.fmw"
	encryptedFixture = "../../testdata/encrypted.fmw"
	fixturePassword  = "fmw-tools test 1"
)

func openT(t *testing.T, path string) *Archive {
	t.Helper()
	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestPluginFixturesVerify(t *testing.T) {
	for _, tc := range []struct {
		path, password string
	}{
		{plainFixture, ""},
		{encryptedFixture, fixturePassword},
	} {
		a := openT(t, tc.path)
		for _, deep := range []bool{false, true} {
			rep, err := a.Verify(tc.password, deep, nil)
			if err != nil {
				t.Fatalf("%s deep=%v: %v", tc.path, deep, err)
			}
			if !rep.OK() || rep.Parts != 17 {
				t.Fatalf("%s deep=%v: %d parts, problems %v", tc.path, deep, rep.Parts, rep.Problems)
			}
		}
	}
}

func TestPluginFixtureManifests(t *testing.T) {
	plain := openT(t, plainFixture)
	enc := openT(t, encryptedFixture)
	if plain.Encrypted() || !enc.Encrypted() {
		t.Fatal("encryption flags are wrong")
	}
	if _, err := enc.Manifest(""); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("no password: %v", err)
	}
	if _, err := enc.Manifest("wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	pm, err := plain.Manifest("")
	if err != nil {
		t.Fatal(err)
	}
	em, err := enc.Manifest(fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pm.Site.HomeURL != "http://127.0.0.1:8090" || em.Site.TablePrefix != "wp_" || !em.Options.Encrypted {
		t.Fatalf("unexpected site data: %+v / %+v", pm.Site, em.Options)
	}
	// Decrypted names are the plain archive's names: the table name comes back.
	var want, got []string
	for _, p := range pm.Parts {
		want = append(want, p.Path)
	}
	for _, p := range em.Parts {
		got = append(got, PlainName(p))
	}
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("plain names differ:\n%v\n%v", want, got)
	}
}

func TestTamperedPartIsReported(t *testing.T) {
	for _, tc := range []struct {
		path, password, want string
	}{
		{plainFixture, "", "SHA-256 mismatch"},
		{encryptedFixture, fixturePassword, "SHA-256 mismatch"},
	} {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		a := openT(t, tc.path)
		m, err := a.Manifest(tc.password)
		if err != nil {
			t.Fatal(err)
		}
		last := m.Parts[len(m.Parts)-1]
		e, _ := a.Container().Lookup(last.Path)
		data[e.Offset+e.Size/2] ^= 0x01
		copyPath := filepath.Join(t.TempDir(), "tampered.fmw")
		if err := os.WriteFile(copyPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		rep, err := openT(t, copyPath).Verify(tc.password, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], tc.want) || !strings.Contains(rep.Problems[0], last.Path) {
			t.Fatalf("%s: problems %v", tc.path, rep.Problems)
		}
	}
}
