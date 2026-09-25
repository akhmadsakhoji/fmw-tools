// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// networkManifest is a manifest of a network with these sites (id, domain, path), with or without site.network.
func networkManifest(t *testing.T, network map[string]any, sites ...[3]any) *Manifest {
	t.Helper()
	var list []map[string]any
	for _, s := range sites {
		list = append(list, map[string]any{"blog_id": s[0], "domain": s[1], "path": s[2]})
	}
	site := map[string]any{"multisite": true, "sites": list, "table_prefix": "wp_", "content_dir": "wp-content", "uploads_dir": "wp-content/uploads"}
	if network != nil {
		site["network"] = network
	}
	raw, _ := json.Marshal(map[string]any{"site": site})
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestNetworkIsReadOrWorkedOutFromTheSites(t *testing.T) {
	m := networkManifest(t, map[string]any{"id": 1, "domain": "Net.Example", "path": "/", "subdomain": true, "main_site": 1, "networks": 1},
		[3]any{1, "net.example", "/"}, [3]any{2, "shop.net.example", "/"})
	n := m.Network()
	if n.Derived || n.Domain != "net.example" || n.Kind() != "subdomains" || n.MainSite != 1 || len(n.Sites) != 2 {
		t.Fatalf("read: %+v", n)
	}

	// Older backups: no site.network.
	for want, sites := range map[string][][3]any{
		"subdirectories": {{1, "old.example", "/"}, {2, "old.example", "/shop"}},
		"subdomains":     {{1, "www.old.example", "/"}, {2, "shop.old.example", "/"}},
		"":               {{1, "old.example", "/"}, {2, "brand.example", "/"}},
	} {
		n := networkManifest(t, nil, sites...).Network()
		if !n.Derived || n.Kind() != want || n.Domain != sites[0][1] || n.MainSite != 1 {
			t.Fatalf("derived %q: %+v", want, n)
		}
	}
	if (&Manifest{}).Network() != nil {
		t.Fatal("a single site has no network")
	}
}

func TestSitesAreFoundByIDAddressOrURL(t *testing.T) {
	n := networkManifest(t, nil, [3]any{1, "net.example", "/"}, [3]any{2, "net.example", "/shop/"}, [3]any{12, "brand.example", "/"}).Network()
	for choice, want := range map[string]int{"2": 2, "net.example/shop": 2, "https://NET.example/shop/": 2, " brand.example ": 12, "http://net.example": 1} {
		s, err := n.Find(choice)
		if err != nil || s.BlogID != want {
			t.Fatalf("%q: %v %v", choice, s, err)
		}
	}
	sub := networkManifest(t, nil, [3]any{1, "net.example", "/"}, [3]any{2, "shop.net.example", "/"}, [3]any{3, "net.example", "/blog/"}, [3]any{4, "net.example", "/shop/"}).Network()
	for choice, want := range map[string]int{"blog": 3, "/blog/": 3, "BLOG": 3} {
		if s, err := sub.Find(choice); err != nil || s.BlogID != want {
			t.Fatalf("short %q: %v %v", choice, s, err)
		}
	}
	if _, err := sub.Find("shop"); err == nil || !strings.Contains(err.Error(), "more than one site is called") {
		t.Fatalf("ambiguous short name: %v", err)
	}
	if s, err := n.Find("shop"); err != nil || s.BlogID != 2 {
		t.Fatalf("short shop: %v %v", s, err)
	}
	if _, err := n.Find("net.example/nope"); err == nil || !strings.Contains(err.Error(), "its sites: 1 net.example/, 2 net.example/shop/, 12 brand.example/") {
		t.Fatalf("unknown site: %v", err)
	}
}

func TestOneSiteTakesItsTablesMediaUsersAndSharedFiles(t *testing.T) {
	m := networkManifest(t, nil, [3]any{1, "net.example", "/"}, [3]any{2, "net.example", "/shop/"}, [3]any{12, "brand.example", "/"})
	pick := func(site string, tables bool, names ...string) []string {
		f, err := NewSiteFilter(m, site)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, name := range names {
			if (tables && f.WantTable(name)) || (!tables && f.WantFile(name)) {
				out = append(out, name)
			}
		}
		return out
	}
	tables := []string{"wp_posts", "wp_options", "wp_users", "wp_usermeta", "wp_sitemeta", "wp_blogs", "wp_2_posts", "wp_12_posts", "wp_2fa_codes", "wp_404_to_301", "views", "other_posts"}
	if got := strings.Join(pick("2", true, tables...), " "); got != "wp_users wp_usermeta wp_2_posts" {
		t.Fatalf("site 2 tables: %s", got)
	}
	if got := strings.Join(pick("1", true, tables...), " "); got != "wp_posts wp_options wp_users wp_usermeta wp_2fa_codes wp_404_to_301" {
		t.Fatalf("site 1 tables: %s", got)
	}
	files := []string{"uploads", "uploads/2026/09/main.jpg", "uploads/sites", "uploads/sites/2/2026/a.jpg", "uploads/sites/12/x.jpg", "uploads/sites/20/y.jpg", "blogs.dir/2/files/old.jpg", "blogs.dir/12/files/z.jpg", "plugins/shop/shop.php", "themes/astra/style.css", "uploads-old/x"}
	if got := strings.Join(pick("net.example/shop", false, files...), " "); got != "uploads uploads/sites uploads/sites/2/2026/a.jpg blogs.dir/2/files/old.jpg plugins/shop/shop.php themes/astra/style.css uploads-old/x" {
		t.Fatalf("site 2 files: %s", got)
	}
	if got := strings.Join(pick("1", false, files...), " "); got != "uploads uploads/2026/09/main.jpg plugins/shop/shop.php themes/astra/style.css uploads-old/x" {
		t.Fatalf("site 1 files: %s", got)
	}
	if _, err := NewSiteFilter(&Manifest{}, "2"); err == nil {
		t.Fatal("--site on a single-site backup was accepted")
	}
}

func TestExtractOneSiteOfANetworkBackup(t *testing.T) {
	parts := []tPart{
		sqlPart(1, "wp_users", "-- users"),
		sqlPart(2, "wp_usermeta", "-- usermeta"),
		sqlPart(3, "wp_blogs", "-- blogs"),
		sqlPart(4, "wp_posts", "-- site 1"),
		sqlPart(5, "wp_2_posts", "-- site 2"),
		sqlPart(6, "wp_3_posts", "-- site 3"),
		sqlPart(7, "views", "-- views"),
		filesPart(t,
			tEntry{name: "plugins/shop/shop.php", body: "<?php"},
			tEntry{name: "uploads/2026/main.jpg", body: "main"},
			tEntry{name: "uploads/sites/2/2026/two.jpg", body: "two"},
			tEntry{name: "uploads/sites/3/2026/three.jpg", body: "three"},
		),
	}
	site := map[string]any{"home_url": "https://net.example", "content_dir": "wp-content", "uploads_dir": "wp-content/uploads", "table_prefix": "wp_", "multisite": true,
		"sites":   []map[string]any{{"blog_id": 1, "domain": "net.example", "path": "/"}, {"blog_id": 2, "domain": "net.example", "path": "/two/"}, {"blog_id": 3, "domain": "net.example", "path": "/three/"}},
		"network": map[string]any{"id": 1, "domain": "net.example", "path": "/", "subdomain": false, "main_site": 1, "networks": 1}}
	for name, ta := range map[string]tArchive{
		"plain":     {parts: parts, manifest: map[string]any{"site": site}},
		"encrypted": {parts: encryptedNames(parts), password: "secret", manifest: map[string]any{"site": site}},
	} {
		path := ta.build(t)
		m, err := openT(t, path).Manifest(ta.password)
		if err != nil {
			t.Fatal(err)
		}
		f, err := NewSiteFilter(m, "net.example/two")
		if err != nil {
			t.Fatal(err)
		}
		dest, _, st, warns, err := extractT(t, path, ta.password, ExtractOptions{Site: f})
		if err != nil || len(warns) > 0 {
			t.Fatalf("%s: %v %v", name, err, warns)
		}
		var sql []string
		entries, _ := os.ReadDir(filepath.Join(dest, "database"))
		for _, e := range entries {
			sql = append(sql, e.Name())
		}
		sort.Strings(sql)
		if strings.Join(sql, " ") != "0001-wp_users.0001.sql.gz 0002-wp_usermeta.0001.sql.gz 0005-wp_2_posts.0001.sql.gz" || st.SQLFiles != 3 {
			t.Fatalf("%s database: %v", name, sql)
		}
		for rel, want := range map[string]bool{"plugins/shop/shop.php": true, "uploads/sites/2/2026/two.jpg": true, "uploads/2026/main.jpg": false, "uploads/sites/3": false} {
			if _, err := os.Stat(filepath.Join(dest, "wp-content", rel)); (err == nil) != want {
				t.Fatalf("%s: %s present=%v", name, rel, err == nil)
			}
		}
	}
}

func TestNetworkValuesWrittenLooselyStillRead(t *testing.T) {
	raw := `{"site":{"multisite":true,"table_prefix":"","sites":[{"blog_id":"1","domain":"n.example","path":"/","network_id":"1"},{"blog_id":"2","domain":"a.n.example","path":"/","network_id":""}],
		"network":{"id":"1","domain":"n.example","path":"/","subdomain":1,"main_site":"1","networks":"2"}}}`
	var m Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("manifest with loose values: %v", err)
	}
	n := m.Network()
	if n.Kind() != "subdomains" || n.MainSite != 1 || n.Networks != 2 || len(n.Sites) != 2 || n.Sites[0].NetworkID != 1 || n.Sites[1].NetworkID != 0 {
		t.Fatalf("loose: %+v", n)
	}
	for in, want := range map[string]string{`true`: "yes", `"yes"`: "yes", `"1"`: "yes", `0`: "no", `"off"`: "no", `false`: "no", `null`: "nil", `"maybe"`: "nil", `[]`: "nil"} {
		got := "nil"
		if b := looseBool(json.RawMessage(in)); b != nil && *b {
			got = "yes"
		} else if b != nil {
			got = "no"
		}
		if got != want {
			t.Fatalf("looseBool(%s) = %s", in, got)
		}
	}

	// An empty table prefix must not let views or triggers into one site's extract.
	f, err := NewSiteFilter(&m, "1")
	if err != nil {
		t.Fatal(err)
	}
	if f.WantTable("views") || f.WantTable("triggers") || f.WantTable("2_posts") || f.WantTable("blogs") || !f.WantTable("posts") || !f.WantTable("users") {
		t.Fatal("empty prefix: wrong tables picked")
	}
}
