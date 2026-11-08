package workflows

import (
	"reflect"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func TestHelpers(t *testing.T) {
	f := Parse("ci.yml", `on:
  pull_request_target:
  push:
jobs:
  a:
    runs-on: x
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: docker://alpine@sha256:abc
      - uses: ./local
      - uses: vendor/x@`+sha+`
  b:
    uses: org/wf/.github/workflows/r.yml@main
`)
	if f.Err != nil {
		t.Fatal(f.Err)
	}
	if !reflect.DeepEqual(f.Triggers(), []string{"pull_request_target", "push"}) {
		t.Fatalf("triggers %v", f.Triggers())
	}
	var pinned, total int
	for _, u := range f.AllUses() {
		total++
		if u.Pinned() {
			pinned++
		}
	}
	if total != 5 || pinned != 3 {
		t.Fatalf("uses %d pinned %d", total, pinned)
	}
	if !f.WriteAll() {
		t.Fatal("write-all not detected")
	}
	if !reflect.DeepEqual(f.PwnRequest(), []string{"a"}) {
		t.Fatalf("pwn %v", f.PwnRequest())
	}
	if !reflect.DeepEqual(f.JobsWithoutPermissions(), []string{"b"}) {
		t.Fatalf("no perms %v", f.JobsWithoutPermissions())
	}
}

func TestStaticKeysAndOIDC(t *testing.T) {
	f := Parse("d.yml", `on: push
permissions:
  id-token: write
jobs:
  d:
    runs-on: x
    steps:
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          aws-access-key-id: ${{ secrets.KEY }}
        env:
          AWS_SECRET_ACCESS_KEY: ${{ secrets.SECRET }}
`)
	if got := f.StaticCloudKeys(); len(got) != 2 {
		t.Fatalf("keys %v", got)
	}
	if !f.UsesOIDC() {
		t.Fatal("oidc not detected")
	}
}
