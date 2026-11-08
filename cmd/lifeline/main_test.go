package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/checks"
)

func TestScanLocalPathAllFormats(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755))
	must(os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v7\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "lifeline.yml"), []byte("backups: []\ncost:\n  monthly_spend_usd: 0\n  budget_alerts: true\n"), 0o644))
	out := filepath.Join(dir, "out")
	var stdout bytes.Buffer
	code, err := cmdScan([]string{"--path", dir, "--format", "text",
		"--json", filepath.Join(out, "r.json"), "--markdown", filepath.Join(out, "r.md"),
		"--sarif", filepath.Join(out, "r.sarif"), "--badge", filepath.Join(out, "badge.json")}, &stdout)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	if !strings.Contains(stdout.String(), "LL-CI-001") {
		t.Fatalf("stdout: %s", stdout.String())
	}
	for _, f := range []string{"r.json", "r.md", "r.sarif", "badge.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("%s not written", f)
		}
	}
	// --previous computes a delta; --fail-under sets the exit code
	stdout.Reset()
	code, err = cmdScan([]string{"--path", dir, "--format", "json", "--previous", filepath.Join(out, "r.json"), "--fail-under", "9.9"}, &stdout)
	if err != nil || code != 1 {
		t.Fatalf("fail-under: code %d err %v", code, err)
	}
	var rep map[string]any
	must(json.Unmarshal(stdout.Bytes(), &rep))
	if rep["delta"].(float64) != 0 {
		t.Fatalf("delta %v", rep["delta"])
	}
}

func TestScanNeedsATarget(t *testing.T) {
	if _, err := cmdScan([]string{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error without targets")
	}
	if _, err := cmdScan([]string{"--repo", "nope"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for bad --repo")
	}
}

func TestSummaryAnonymised(t *testing.T) {
	s := summary(nil, false)
	if !strings.Contains(s, "0 projects") {
		t.Fatal(s)
	}
}

func TestRepoValidation(t *testing.T) {
	for repo, ok := range map[string]bool{
		"kubernetes/kubernetes": true,
		"a-b/c.d_e":             true,
		"owner/.github":         true,
		"../x":                  false,
		"a/..":                  false,
		"a/b/c":                 false,
		"a/b?per_page=1":        false,
		"-bad/name":             false,
		"nope":                  false,
	} {
		if got := repoRe.MatchString(repo); got != ok {
			t.Errorf("repoRe(%q) = %v, want %v", repo, got, ok)
		}
	}
}

func TestSARIFLocationIsRepoRelative(t *testing.T) {
	dir := t.TempDir() // absolute, like $GITHUB_WORKSPACE in the action
	if err := os.WriteFile(filepath.Join(dir, "lifeline.yml"), []byte("project: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "r.sarif")
	if code, err := cmdScan([]string{"--path", dir, "--format", "badge", "--sarif", out}, &bytes.Buffer{}); err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), dir) || !strings.Contains(string(b), `"uri": "lifeline.yml"`) {
		t.Fatalf("SARIF must use repository-relative paths:\n%s", b)
	}
}

func TestSummaryLeavesOutLowCoverage(t *testing.T) {
	reps := []*checks.Report{
		{Repo: "a/a", Score: 8, Coverage: 0.9},
		{Repo: "b/b", Score: 6, Coverage: 0.7},
		{Repo: "c/c", Score: 0, Coverage: 0.1}, // rate-limited scan
	}
	s := summary(reps, true)
	for _, want := range []string{"Median score **7.0/10**", "over 2 project(s)", "1 project(s) with coverage below 50%", "| c/c | 0.0 | 10% |"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}

func TestUnknownFormatFailsBeforeScanning(t *testing.T) {
	start := time.Now()
	code, err := cmdScan([]string{"--domain", "example.invalid", "--format", "yaml"}, &bytes.Buffer{})
	if err == nil || code != 2 || !strings.Contains(err.Error(), "unknown --format") {
		t.Fatalf("code %d err %v", code, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the format must be validated before any network work")
	}
}
