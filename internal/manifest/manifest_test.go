package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFull(t *testing.T) {
	m, err := Parse(`project: demo
domain: Example.ORG.
security_contact: security@example.org
backups:
  - name: db
    isolated: no
    last_restore_test: 2026-09-01
cost:
  monthly_spend_usd: "1,200"
  budget_alerts: true
ignore:
  - ll-dom-004  # no DNSSEC support at our registrar
`)
	if err != nil {
		t.Fatal(err)
	}
	if m.Domain != "example.org" || m.SecurityContact == "" || !m.Found {
		t.Fatalf("%+v", m)
	}
	if len(m.Backups) != 1 || m.Backups[0].Isolated || !m.Backups[0].IsolatedSet || m.Backups[0].LastRestoreTest.Day() != 1 {
		t.Fatalf("backups %+v", m.Backups)
	}
	if m.Cost.MonthlySpendUSD != 1200 || !m.Cost.BudgetAlerts {
		t.Fatalf("cost %+v", m.Cost)
	}
	if !m.Ignore["LL-DOM-004"] {
		t.Fatalf("ignore %+v", m.Ignore)
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{
		"backups:\n  - name: x\n    last_restore_test: yesterday\n",
		"cost:\n  monthly_spend_usd: lots\n",
		"backups:\n  - just-a-string\n",
	} {
		if _, err := Parse(src); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

func TestLoadDefaultsAndMissing(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir, "")
	if err != nil || m.Found {
		t.Fatalf("missing file should be fine: %+v %v", m, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "lifeline.yml"), []byte("project: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err = Load(dir, "")
	if err != nil || !m.Found || m.Project != "x" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := Load(dir, filepath.Join(dir, "nope.yml")); err == nil {
		t.Fatal("explicit missing config must error")
	}
}

func TestIgnoreWildcardAndUnknownKeys(t *testing.T) {
	m, err := Parse(`ignore:
  - LL-BAK-*   # no stateful data
  - ll-cost-002
backups:
  - name: db
    last_restore_tested: 2026-01-01
cots:
  monthly_spend_usd: 5
`)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"LL-BAK-001": true, "LL-BAK-003": true, "ll-bak-002": true, "LL-COST-002": true, "LL-COST-001": false, "LL-BA": false} {
		if got := m.Ignores(id); got != want {
			t.Errorf("Ignores(%s) = %v, want %v", id, got, want)
		}
	}
	if len(m.Warnings) != 2 {
		t.Fatalf("warnings %v", m.Warnings)
	}
	if want := `"backups[0].last_restore_tested"`; !contains(m.Warnings, want) || !contains(m.Warnings, `"cots"`) {
		t.Fatalf("warnings %v", m.Warnings)
	}
	var nilManifest *Manifest
	if nilManifest.Ignores("LL-DOM-001") {
		t.Fatal("nil manifest ignores nothing")
	}
}

func contains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestRelPathForSARIF(t *testing.T) {
	dir := t.TempDir() // absolute
	if err := os.WriteFile(filepath.Join(dir, "lifeline.yml"), []byte("project: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Load(dir, "")
	if err != nil || m.RelPath != "lifeline.yml" {
		t.Fatalf("default path: %q %v", m.RelPath, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "ops"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ops", "resilience.yml")
	if err := os.WriteFile(cfg, []byte("project: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err = Load(dir, cfg)
	if err != nil || m.RelPath != "ops/resilience.yml" {
		t.Fatalf("explicit path: %q %v", m.RelPath, err)
	}
}

func TestBooleanTypoWarns(t *testing.T) {
	m, err := Parse("backups:\n  - name: db\n    isolated: tru\ncost:\n  budget_alerts: yes\n")
	if err != nil {
		t.Fatal(err)
	}
	if m.Backups[0].Isolated || !m.Cost.BudgetAlerts || len(m.Warnings) != 1 || !strings.Contains(m.Warnings[0], "backups[0].isolated") {
		t.Fatalf("%+v %v", m.Backups, m.Warnings)
	}
}
