package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/checks"
)

func sample() *checks.Report {
	d := -1.5
	return &checks.Report{
		Tool: "lifeline", Version: "test", GeneratedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC),
		Repo: "acme/app", Domain: "acme.example", Score: 6.2, Coverage: 0.7, Delta: &d,
		Categories: map[string]float64{checks.CatCI: 6.2},
		Results: []checks.Result{
			{ID: "LL-CI-001", Category: checks.CatCI, Title: "Pinned", Status: checks.Fail, Score: 2, Weight: 8, Summary: "2 of 10 | pinned", Details: []string{"a.yml: x@v1"}, Location: ".github/workflows/a.yml", Remediation: "pin"},
			{ID: "LL-CI-002", Category: checks.CatCI, Title: "Perms", Status: checks.Pass, Score: 10, Weight: 6, Summary: "ok"},
			{ID: "LL-DOM-001", Category: checks.CatDomain, Title: "Expiry", Status: checks.Skip, Score: -1, Weight: 10, Summary: "no domain"},
		},
	}
}

func TestSARIF(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(SARIF(sample(), checks.All())), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("only warn/fail results belong in SARIF, got %d", len(results))
	}
	r := results[0].(map[string]any)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	idx := int(r["ruleIndex"].(float64))
	if rules[idx].(map[string]any)["id"] != r["ruleId"] {
		t.Fatal("ruleIndex does not point at the rule")
	}
}

func TestMarkdownTextBadge(t *testing.T) {
	md := Markdown(sample())
	for _, want := range []string{"6.2 / 10", "fragile", "-1.5", "What to fix first", `2 of 10 \| pinned`} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if !strings.Contains(Text(sample()), "[FAIL] LL-CI-001") {
		t.Error("text output")
	}
	var b map[string]any
	if err := json.Unmarshal([]byte(Badge(sample())), &b); err != nil || b["message"] != "6.2/10" || b["color"] != "yellow" {
		t.Errorf("badge = %v %v", b, err)
	}
}

func TestHTMLEscapes(t *testing.T) {
	r := sample()
	r.Results[0].Summary = "<script>alert(1)</script>"
	page := HTML(r)
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("HTML output must escape untrusted text")
	}
}

func TestNothingEvaluated(t *testing.T) {
	r := sample()
	r.Score, r.Coverage = 0, 0
	if !strings.Contains(Text(r), "(not evaluated)  coverage 0%") {
		t.Errorf("text: %s", Text(r))
	}
	var b map[string]any
	if err := json.Unmarshal([]byte(Badge(r)), &b); err != nil || b["color"] != "lightgrey" || b["message"] != "not evaluated" {
		t.Errorf("badge = %v %v", b, err)
	}
}
