package yamlite

import (
	"reflect"
	"testing"
)

func mustMap(t *testing.T, src string) map[string]any {
	t.Helper()
	m, err := ParseMap(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return m
}

func TestWorkflow(t *testing.T) {
	src := `# CI
name: CI
on:
  push:
    branches: [main, "release/*"]
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v7 # pinned later
        with:
          persist-credentials: false
      - name: "Say: hi"
        run: |
          echo "a: b"   # not a comment inside a block scalar
          echo two

      - run: echo one-liner
      - uses: actions/setup-go@v7
        with: { go-version-file: go.mod, cache: true }
`
	m := mustMap(t, src)
	if m["name"] != "CI" {
		t.Fatalf("name = %#v", m["name"])
	}
	on := m["on"].(map[string]any)
	if !reflect.DeepEqual(on["push"].(map[string]any)["branches"], []any{"main", "release/*"}) {
		t.Fatalf("branches = %#v", on["push"])
	}
	if v, ok := on["pull_request"]; !ok || v != nil {
		t.Fatalf("pull_request = %#v (present=%v)", v, ok)
	}
	steps := m["jobs"].(map[string]any)["build"].(map[string]any)["steps"].([]any)
	if len(steps) != 4 {
		t.Fatalf("steps = %d: %#v", len(steps), steps)
	}
	s0 := steps[0].(map[string]any)
	if s0["uses"] != "actions/checkout@v7" || s0["with"].(map[string]any)["persist-credentials"] != "false" {
		t.Fatalf("step0 = %#v", s0)
	}
	s1 := steps[1].(map[string]any)
	if s1["name"] != "Say: hi" {
		t.Fatalf("quoted name = %#v", s1["name"])
	}
	want := "echo \"a: b\"   # not a comment inside a block scalar\necho two\n"
	if s1["run"] != want {
		t.Fatalf("run = %q, want %q", s1["run"], want)
	}
	if steps[2].(map[string]any)["run"] != "echo one-liner" {
		t.Fatalf("step2 = %#v", steps[2])
	}
	with := steps[3].(map[string]any)["with"].(map[string]any)
	if with["go-version-file"] != "go.mod" || with["cache"] != "true" {
		t.Fatalf("flow map = %#v", with)
	}
}

func TestOnAsStringAndList(t *testing.T) {
	if m := mustMap(t, "on: push\n"); m["on"] != "push" {
		t.Fatalf("%#v", m)
	}
	m := mustMap(t, "on: [push, pull_request_target]\n")
	if !reflect.DeepEqual(m["on"], []any{"push", "pull_request_target"}) {
		t.Fatalf("%#v", m["on"])
	}
}

func TestSequenceAtSameIndent(t *testing.T) {
	m := mustMap(t, "updates:\n- package-ecosystem: github-actions\n  directory: /\n- package-ecosystem: pip\n")
	u := m["updates"].([]any)
	if len(u) != 2 || u[1].(map[string]any)["package-ecosystem"] != "pip" || u[0].(map[string]any)["directory"] != "/" {
		t.Fatalf("%#v", u)
	}
}

func TestNestedSequences(t *testing.T) {
	m := mustMap(t, "a:\n  - - x\n    - y\n  - z\n")
	want := []any{[]any{"x", "y"}, "z"}
	if !reflect.DeepEqual(m["a"], want) {
		t.Fatalf("%#v", m["a"])
	}
}

func TestBlockScalarChomping(t *testing.T) {
	m := mustMap(t, "a: |-\n  one\n  two\n\nb: >\n  folded\n  text\n\n  para\nc: |+\n  keep\n\nd: x\n")
	if m["a"] != "one\ntwo" {
		t.Fatalf("a = %q", m["a"])
	}
	if m["b"] != "folded text\n\npara\n" {
		t.Fatalf("b = %q", m["b"])
	}
	if m["c"] != "keep\n\n" {
		t.Fatalf("c = %q", m["c"])
	}
	if m["d"] != "x" {
		t.Fatalf("d = %q", m["d"])
	}
}

func TestQuotes(t *testing.T) {
	m := mustMap(t, `a: 'it''s'`+"\n"+`b: "tab\there \"q\" \u00e9"`+"\n"+`"c d": x # comment`+"\n"+`e: '#not comment'`+"\n")
	if m["a"] != "it's" || m["b"] != "tab\there \"q\" é" || m["c d"] != "x" || m["e"] != "#not comment" {
		t.Fatalf("%#v", m)
	}
}

func TestMultilineFlowAndNulls(t *testing.T) {
	m := mustMap(t, "branches: [main,\n  dev]\nx: ~\ny:\nz: null\nurl: https://example.com/a#b\n")
	if !reflect.DeepEqual(m["branches"], []any{"main", "dev"}) {
		t.Fatalf("%#v", m["branches"])
	}
	for _, k := range []string{"x", "y", "z"} {
		if v, ok := m[k]; !ok || v != nil {
			t.Fatalf("%s = %#v", k, v)
		}
	}
	if m["url"] != "https://example.com/a#b" {
		t.Fatalf("url = %#v", m["url"])
	}
}

func TestPlainContinuation(t *testing.T) {
	m := mustMap(t, "desc: this is\n  continued here\nnext: 1\n")
	if m["desc"] != "this is continued here" || m["next"] != "1" {
		t.Fatalf("%#v", m)
	}
}

func TestDocumentMarkerAndEmpty(t *testing.T) {
	if m := mustMap(t, "---\na: b\n"); m["a"] != "b" {
		t.Fatalf("%#v", m)
	}
	if m := mustMap(t, "# only a comment\n"); len(m) != 0 {
		t.Fatalf("%#v", m)
	}
}

func TestErrors(t *testing.T) {
	if _, err := Parse("a: [unclosed\n"); err == nil {
		t.Fatal("expected error for unclosed flow sequence")
	}
	if _, err := Parse("a: 'unterminated\n"); err == nil {
		t.Fatal("expected error for unterminated quote")
	}
}

func TestSeqOfMapsWithNestedMaps(t *testing.T) {
	src := `jobs:
  deploy:
    environment:
      name: prod
      url: ${{ steps.d.outputs.url }}
    steps:
      - id: d
        uses: actions/deploy-pages@v5
`
	m := mustMap(t, src)
	dep := m["jobs"].(map[string]any)["deploy"].(map[string]any)
	if dep["environment"].(map[string]any)["url"] != "${{ steps.d.outputs.url }}" {
		t.Fatalf("%#v", dep)
	}
	st := dep["steps"].([]any)[0].(map[string]any)
	if st["id"] != "d" || st["uses"] != "actions/deploy-pages@v5" {
		t.Fatalf("%#v", st)
	}
}
