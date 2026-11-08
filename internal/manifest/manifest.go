// Package manifest reads lifeline.yml: the facts Lifeline cannot discover
// from the outside (backups, restore tests, cost runway).
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/yamlite"
)

// DefaultPaths are tried in order when no --config is given.
var DefaultPaths = []string{"lifeline.yml", "lifeline.yaml", ".github/lifeline.yml", ".github/lifeline.yaml"}

// Backup describes one backup the project keeps.
type Backup struct {
	Name            string
	What            string
	Location        string
	Isolated        bool
	IsolatedSet     bool
	LastRestoreTest time.Time
}

// Cost describes how long the project's infrastructure money lasts.
type Cost struct {
	Set             bool
	MonthlySpendUSD float64
	CreditsUSD      float64
	CashUSD         float64
	CreditsExpire   time.Time
	BudgetAlerts    bool
	BudgetAlertsSet bool
}

// Manifest is the parsed lifeline.yml.
type Manifest struct {
	Path            string // as opened (may be absolute)
	RelPath         string // relative to the scanned checkout, with forward slashes (for SARIF)
	Found           bool
	Project         string
	Domain          string
	SecurityContact string
	BackupsSet      bool
	Backups         []Backup
	Cost            Cost
	DKIMSelectors   []string        // DKIM selectors to check besides the common ones (LL-DOM-006)
	Ignore          map[string]bool // check IDs, or prefixes ending in "*" such as "LL-BAK-*"
	Warnings        []string        // unknown keys (usually typos), printed by the CLI
}

// Ignores reports whether a check ID is listed under `ignore:`, either exactly
// or through a wildcard entry such as "LL-BAK-*".
func (m *Manifest) Ignores(id string) bool {
	if m == nil {
		return false
	}
	id = strings.ToUpper(id)
	if m.Ignore[id] {
		return true
	}
	for k := range m.Ignore {
		if strings.HasSuffix(k, "*") && strings.HasPrefix(id, strings.TrimSuffix(k, "*")) {
			return true
		}
	}
	return false
}

// Load reads path, or the first default path that exists under root when path is "".
// A missing file is not an error: Found is false.
func Load(root, path string) (*Manifest, error) {
	candidates := []string{path}
	if path == "" {
		candidates = nil
		for _, p := range DefaultPaths {
			candidates = append(candidates, joinPath(root, p))
		}
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		m, err := Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		m.Path = p
		m.RelPath = relTo(root, p)
		return m, nil
	}
	if path != "" {
		return nil, fmt.Errorf("config file %s not found", path)
	}
	return &Manifest{Ignore: map[string]bool{}}, nil
}

// relTo returns p relative to root with forward slashes, or p's base name
// when it lies outside root (a SARIF location must be inside the repository).
func relTo(root, p string) string {
	if root == "" {
		root = "."
	}
	ar, err1 := filepath.Abs(root)
	ap, err2 := filepath.Abs(p)
	if err1 == nil && err2 == nil {
		if rel, err := filepath.Rel(ar, ap); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.Base(p)
}

func joinPath(root, p string) string {
	if root == "" || root == "." {
		return p
	}
	return strings.TrimRight(root, "/") + "/" + p
}

// Parse parses manifest text.
func Parse(src string) (*Manifest, error) {
	doc, err := yamlite.ParseMap(src)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Found: true, Ignore: map[string]bool{}}
	m.unknown("", doc, "project", "domain", "security_contact", "dkim_selectors", "backups", "cost", "ignore")
	m.Project = str(doc["project"])
	m.Domain = strings.TrimSuffix(strings.ToLower(str(doc["domain"])), ".")
	m.SecurityContact = str(doc["security_contact"])

	if raw, ok := doc["backups"]; ok {
		m.BackupsSet = true
		list, _ := raw.([]any)
		for i, item := range list {
			b, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("backups[%d] must be a mapping", i)
			}
			m.unknown(fmt.Sprintf("backups[%d].", i), b, "name", "what", "location", "isolated", "last_restore_test")
			bk := Backup{Name: str(b["name"]), What: str(b["what"]), Location: str(b["location"])}
			if v, ok := b["isolated"]; ok && v != nil {
				bk.IsolatedSet = true
				bk.Isolated = m.boolean(fmt.Sprintf("backups[%d].isolated", i), str(v))
			}
			if d := str(b["last_restore_test"]); d != "" {
				t, err := parseDate(d)
				if err != nil {
					return nil, fmt.Errorf("backups[%d].last_restore_test: %w", i, err)
				}
				bk.LastRestoreTest = t
			}
			if bk.Name == "" {
				bk.Name = fmt.Sprintf("backup %d", i+1)
			}
			m.Backups = append(m.Backups, bk)
		}
	}

	if raw, ok := doc["cost"].(map[string]any); ok {
		c := &m.Cost
		c.Set = true
		m.unknown("cost.", raw, "monthly_spend_usd", "credits_remaining_usd", "credits_expire", "cash_remaining_usd", "budget_alerts")
		var err error
		if c.MonthlySpendUSD, err = num(raw, "monthly_spend_usd"); err != nil {
			return nil, err
		}
		if c.CreditsUSD, err = num(raw, "credits_remaining_usd"); err != nil {
			return nil, err
		}
		if c.CashUSD, err = num(raw, "cash_remaining_usd"); err != nil {
			return nil, err
		}
		if d := str(raw["credits_expire"]); d != "" {
			if c.CreditsExpire, err = parseDate(d); err != nil {
				return nil, fmt.Errorf("cost.credits_expire: %w", err)
			}
		}
		if v, ok := raw["budget_alerts"]; ok && v != nil {
			c.BudgetAlertsSet = true
			c.BudgetAlerts = m.boolean("cost.budget_alerts", str(v))
		}
	}

	if list, ok := doc["dkim_selectors"].([]any); ok {
		for _, x := range list {
			if s := strings.ToLower(str(x)); s != "" {
				m.DKIMSelectors = append(m.DKIMSelectors, strings.Fields(s)[0])
			}
		}
	}

	if list, ok := doc["ignore"].([]any); ok {
		for _, x := range list {
			if s := str(x); s != "" {
				m.Ignore[strings.ToUpper(strings.Fields(s)[0])] = true
			}
		}
	}
	return m, nil
}

// unknown records keys that Lifeline does not read, so a typo such as
// `last_restore_tested` is reported instead of silently ignored.
func (m *Manifest) unknown(prefix string, doc map[string]any, known ...string) {
	ok := map[string]bool{}
	for _, k := range known {
		ok[k] = true
	}
	var extra []string
	for k := range doc {
		if !ok[k] {
			extra = append(extra, prefix+k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		m.Warnings = append(m.Warnings, fmt.Sprintf("lifeline.yml: unknown key %q (typo?) is ignored", k))
	}
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// boolean reads a YAML boolean. Anything that is not clearly true counts as
// false (the cautious reading), and a value that is neither true nor false
// produces a warning: "isolated: tru" must not silently mean "not isolated".
func (m *Manifest) boolean(key, s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	}
	m.Warnings = append(m.Warnings, fmt.Sprintf("lifeline.yml: %s is %q, read as false (use true or false)", key, s))
	return false
}

func num(m map[string]any, key string) (float64, error) {
	s := strings.ReplaceAll(str(m[key]), ",", "")
	if s == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("cost.%s: %q is not a number", key, s)
	}
	return f, nil
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not a date (use YYYY-MM-DD)", s)
}
