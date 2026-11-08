package netcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestJoinTXT(t *testing.T) {
	cases := map[string]string{
		`"v=spf1 include:a" " -all"`: "v=spf1 include:a -all",
		`"say \"hi\""`:               `say "hi"`,
		`plain`:                      "plain",
	}
	for in, want := range cases {
		if got := JoinTXT(in); got != want {
			t.Errorf("JoinTXT(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestParents(t *testing.T) {
	got := Parents("a.b.example.org.")
	want := []string{"a.b.example.org", "b.example.org", "example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if len(Parents("org")) != 0 {
		t.Fatal("TLD alone has no parents to check")
	}
}

func TestResolverFallsBack(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/dns-json" {
			t.Errorf("accept header %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(`{"Status":0,"AD":true,"Answer":[{"name":"x","type":16,"data":"\"v=spf1 -all\""}]}`))
	}))
	defer good.Close()
	r := &Resolver{Endpoints: []string{bad.URL, good.URL}, HTTP: http.DefaultClient}
	txt, err := r.TXT(context.Background(), "example.org")
	if err != nil || len(txt) != 1 || txt[0] != "v=spf1 -all" {
		t.Fatalf("%v %v", txt, err)
	}
}

func TestSecurityTxt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			_, _ = w.Write([]byte("Contact: mailto:sec@example.org\nExpires: 2027-01-01T00:00:00Z\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	got, err := SecurityTxt(context.Background(), srv.Client(), srv.URL)
	if err != nil || len(got) != 1 || got[0] != "mailto:sec@example.org" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestGuessApex(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.org":     "example.org",
		"example.org":         "example.org",
		"a.b.example.co.uk":   "example.co.uk",
		"example.co.uk":       "example.co.uk",
		"docs.project.co.in":  "project.co.in",
		"WWW.Example.Com.":    "example.com",
		"localhost":           "localhost",
		"deep.sub.example.io": "example.io",
	} {
		if got := GuessApex(in); got != want {
			t.Errorf("GuessApex(%q) = %q, want %q", in, got, want)
		}
	}
}
