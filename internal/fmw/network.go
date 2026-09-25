// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// NetworkSite is one site of a multisite network backup.
type NetworkSite struct {
	BlogID    int    `json:"blog_id"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	NetworkID int    `json:"network_id,omitempty"`
}

// Address is the site's domain and path without the trailing slash
// (example.com, example.com/shop).
func (s NetworkSite) Address() string {
	return strings.TrimSuffix(s.Domain+s.Path, "/")
}

// Network describes the network a backup was made of (format v1, site.network).
// Backups made before site.network existed get it worked out from their
// sites: site 1 is the main site, a site in a folder of its domain means
// subdirectories, a site on a subdomain of it means subdomains.
type Network struct {
	ID        int           `json:"id"`
	Domain    string        `json:"domain"`
	Path      string        `json:"path"`
	Subdomain *bool         `json:"subdomain"` // nil when the sites do not tell.
	MainSite  int           `json:"main_site"`
	Networks  int           `json:"networks"`
	Sites     []NetworkSite `json:"sites"`
	Derived   bool          `json:"derived"` // Worked out from the sites (older backup).
}

// Kind is "subdomains", "subdirectories" or "" when not known.
func (n *Network) Kind() string {
	switch {
	case n.Subdomain == nil:
		return ""
	case *n.Subdomain:
		return "subdomains"
	default:
		return "subdirectories"
	}
}

// looseInt reads a number the plugin wrote as a number or a string (PHP casts loosely too).
func looseInt(raw json.RawMessage, fallback int) int {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return fallback
	}
	switch x := v.(type) {
	case float64:
		if x == float64(int(x)) {
			return int(x)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return fallback
}

// looseBool reads SUBDOMAIN_INSTALL as WordPress may hold it: true, 1, "1", "true" or "yes"; nil when absent.
func looseBool(raw json.RawMessage) *bool {
	var v any
	if json.Unmarshal(raw, &v) != nil || v == nil {
		return nil
	}
	yes := false
	switch x := v.(type) {
	case bool:
		yes = x
	case float64:
		yes = x != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes", "on":
			yes = true
		case "", "0", "false", "no", "off":
		default:
			return nil
		}
	default:
		return nil
	}
	return &yes
}

// looseString reads a string, or "" for anything else.
func looseString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// Network returns the backup's network, or nil for a single site.
func (m *Manifest) Network() *Network {
	s := m.Site
	if !s.Multisite {
		return nil
	}
	n := &Network{ID: 1, Networks: 1, MainSite: 1, Sites: []NetworkSite{}}
	for _, site := range s.Sites {
		id, err := strconv.Atoi(string(site.BlogID))
		if err != nil || id < 1 {
			continue
		}
		n.Sites = append(n.Sites, NetworkSite{BlogID: id, Domain: strings.ToLower(site.Domain), Path: slashed(site.Path), NetworkID: looseInt(site.NetworkID, 0)})
	}
	var recorded map[string]json.RawMessage
	if json.Unmarshal(s.Network, &recorded) == nil && looseString(recorded["domain"]) != "" {
		n.ID = looseInt(recorded["id"], 1)
		n.Domain = strings.ToLower(looseString(recorded["domain"]))
		n.Path = slashed(looseString(recorded["path"]))
		n.Subdomain = looseBool(recorded["subdomain"])
		n.MainSite = looseInt(recorded["main_site"], 1)
		n.Networks = looseInt(recorded["networks"], 1)
		return n
	}
	n.Derived = true
	for _, site := range n.Sites {
		if site.BlogID == 1 {
			n.Domain, n.Path = site.Domain, site.Path
		}
	}
	if n.Domain == "" && len(n.Sites) > 0 {
		n.Domain, n.Path, n.MainSite = n.Sites[0].Domain, n.Sites[0].Path, n.Sites[0].BlogID
	}
	base := strings.TrimPrefix(n.Domain, "www.")
	for _, site := range n.Sites {
		if site.Domain == n.Domain && site.Path != n.Path {
			no := false
			n.Subdomain = &no
			break
		}
		if site.Domain != n.Domain && len(site.Domain) > len(base)+1 && strings.HasSuffix(site.Domain, "."+base) {
			yes := true
			n.Subdomain = &yes
		}
	}
	return n
}

// Find returns the site with this ID, address (shop.example.com,
// example.com/shop or a URL) or short name (shop).
func (n *Network) Find(choice string) (NetworkSite, error) {
	c := strings.ToLower(strings.TrimSpace(choice))
	address := strings.TrimSuffix(schemeRE.ReplaceAllString(c, ""), "/")
	id, idErr := strconv.Atoi(c)
	for _, s := range n.Sites {
		if (idErr == nil && id == s.BlogID) || s.Address() == address {
			return s, nil
		}
	}
	// A short name: the site's folder (shop for example.com/shop/) or the
	// first label of its subdomain (shop for shop.example.com), when only one
	// site has it.
	if short := strings.Trim(address, "/"); short != "" && idErr != nil && !strings.ContainsAny(short, "/.:") {
		var found []NetworkSite
		for _, s := range n.Sites {
			if s.Path == "/"+short+"/" || (s.Path == "/" && strings.HasPrefix(s.Domain, short+".") && s.Domain != n.Domain) {
				found = append(found, s)
			}
		}
		if len(found) == 1 {
			return found[0], nil
		}
		if len(found) > 1 {
			return NetworkSite{}, fmt.Errorf("more than one site is called %q; give its ID or full address: %s", printable(choice), (&Network{Sites: found}).Listing(50))
		}
	}
	return NetworkSite{}, fmt.Errorf("the backup has no site %q; its sites: %s", printable(choice), n.Listing(50))
}

var schemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)

// Listing is "1 example.com/, 2 example.com/shop/" for the first max sites.
func (n *Network) Listing(max int) string {
	var out []string
	for i, s := range n.Sites {
		if i == max {
			out = append(out, fmt.Sprintf("and %d more", len(n.Sites)-max))
			break
		}
		out = append(out, fmt.Sprintf("%d %s", s.BlogID, printable(s.Domain+s.Path)))
	}
	return strings.Join(out, ", ")
}

func slashed(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return "/"
	}
	return "/" + p + "/"
}

// networkTables are the tables of the network itself, not of one of its sites.
var networkTables = map[string]bool{"blogs": true, "blogmeta": true, "site": true, "sitemeta": true, "signups": true, "registration_log": true, "sitecategories": true}

var siteTableRE = regexp.MustCompile(`^([1-9][0-9]*)_(.+)$`)

// SiteFilter picks what belongs to one site of a network backup: its own
// tables and media, the users (shared by the network), and the files every
// site shares (plugins, themes, ...). Names and paths stay as they are in
// the network; the plugin turns them into a single site (wp fmw restore --site).
type SiteFilter struct {
	Site    NetworkSite
	prefix  string
	uploads string // Uploads folder relative to wp-content ("uploads").
	main    int
	ids     map[int]bool
}

// NewSiteFilter chooses one site of the backup's network.
func NewSiteFilter(m *Manifest, choice string) (*SiteFilter, error) {
	n := m.Network()
	if n == nil {
		return nil, fmt.Errorf("--site is for backups of a multisite network; this is a backup of a single site")
	}
	site, err := n.Find(choice)
	if err != nil {
		return nil, err
	}
	f := &SiteFilter{Site: site, prefix: m.Site.TablePrefix, uploads: UploadsFolder(m), main: n.MainSite, ids: map[int]bool{}}
	for _, s := range n.Sites {
		f.ids[s.BlogID] = true
	}
	return f, nil
}

// UploadsFolder is the uploads folder relative to wp-content ("uploads").
func UploadsFolder(m *Manifest) string {
	content := strings.Trim(m.Site.ContentDir, "/")
	if content == "" {
		content = "wp-content"
	}
	uploads := strings.Trim(m.Site.UploadsDir, "/")
	if uploads == "" {
		uploads = "wp-content/uploads"
	}
	if strings.HasPrefix(uploads, content+"/") {
		return strings.TrimPrefix(uploads, content+"/")
	}
	return "uploads"
}

// WantTable tells whether a database part's table belongs to the site: its
// own tables (wp_2_posts; site 1 has the bare prefix), users and usermeta.
// The network's tables, other sites' tables, views and triggers stay out.
func (f *SiteFilter) WantTable(table string) bool {
	if table == "views" || table == "triggers" || !strings.HasPrefix(table, f.prefix) {
		return false
	}
	rest := strings.TrimPrefix(table, f.prefix)
	if m := siteTableRE.FindStringSubmatch(rest); m != nil {
		if id, err := strconv.Atoi(m[1]); err == nil && f.ids[id] {
			return id == f.Site.BlogID
		}
	}
	if rest == "users" || rest == "usermeta" {
		return true
	}
	if networkTables[rest] {
		return false
	}
	return f.Site.BlogID == 1 // The bare prefix is site 1's (and plugin tables such as wp_2fa_codes).
}

// WantFile tells whether a file (relative to wp-content) belongs to the site:
// its media (uploads/sites/<id>/, blogs.dir/<id>/files/ on old networks, or
// the uploads folder itself for the main site) and everything outside the
// uploads folder, which the sites share.
func (f *SiteFilter) WantFile(rel string) bool {
	if rel == "blogs.dir" || strings.HasPrefix(rel, "blogs.dir/") {
		own := fmt.Sprintf("blogs.dir/%d/files", f.Site.BlogID)
		return f.Site.BlogID != f.main && (rel == "blogs.dir" || rel == fmt.Sprintf("blogs.dir/%d", f.Site.BlogID) || rel == own || strings.HasPrefix(rel, own+"/"))
	}
	if f.uploads == "" || (rel != f.uploads && !strings.HasPrefix(rel, f.uploads+"/")) {
		return true // Plugins, themes, languages and other folders are shared by the network.
	}
	sites := f.uploads + "/sites"
	if rel == sites || strings.HasPrefix(rel, sites+"/") {
		own := fmt.Sprintf("%s/%d", sites, f.Site.BlogID)
		return f.Site.BlogID != f.main && (rel == sites || rel == own || strings.HasPrefix(rel, own+"/"))
	}
	return rel == f.uploads || f.Site.BlogID == f.main // uploads/2026/... is the main site's media.
}
