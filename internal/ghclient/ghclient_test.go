package ghclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func client(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}
}

func TestGetRepoSendsHeaders(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-GitHub-Api-Version") == "" {
			http.Error(w, "missing headers", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"full_name":"acme/app","default_branch":"main","owner":{"login":"acme","type":"Organization"}}`)
	})
	r, err := c.GetRepo(context.Background(), "acme/app")
	if err != nil || r.DefaultBranch != "main" || r.Owner.Type != "Organization" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestErrorKinds(t *testing.T) {
	cases := []struct {
		status int
		header string
		body   string
		want   error
	}{
		{404, "", `{"message":"Not Found"}`, ErrNotFound},
		{403, "", `{"message":"Must have admin rights"}`, ErrForbidden},
		{401, "", `{"message":"Bad credentials"}`, ErrBadToken},
		{403, "0", `{"message":"API rate limit exceeded for 203.0.113.9"}`, ErrRateLimited},
		{403, "", `{"message":"You have exceeded a secondary rate limit"}`, ErrRateLimited},
		{429, "", `{}`, ErrRateLimited},
	}
	for _, tc := range cases {
		c := client(t, func(w http.ResponseWriter, r *http.Request) {
			if tc.header != "" {
				w.Header().Set("X-RateLimit-Remaining", tc.header)
			}
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		})
		_, err := c.GetRepo(context.Background(), "acme/app")
		if !errors.Is(err, tc.want) {
			t.Errorf("HTTP %d %q: got %v, want %v", tc.status, tc.body, err, tc.want)
		}
		if tc.want == ErrForbidden && errors.Is(err, ErrRateLimited) {
			t.Errorf("HTTP %d: a permission error must not look like a rate limit", tc.status)
		}
	}
}

func TestFileTextAndListDir(t *testing.T) {
	content := "on: push\njobs: {}\n"
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/contents/ci.yml":
			// GitHub wraps base64 content at 60 characters.
			_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": enc[:10] + "\n" + enc[10:]})
		default:
			http.NotFound(w, r)
		}
	})
	got, err := c.FileText(context.Background(), "acme/app", "ci.yml")
	if err != nil || got != content {
		t.Fatalf("%q %v", got, err)
	}
	entries, err := c.ListDir(context.Background(), "acme/app", ".github/workflows")
	if err != nil || entries != nil {
		t.Fatalf("missing directory must be an empty list: %v %v", entries, err)
	}
	if _, err := c.FileText(context.Background(), "acme/app", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestCommitAuthorsSkipsBotsAndPaginates(t *testing.T) {
	type commit map[string]any
	human := func(login string) commit {
		return commit{"author": map[string]string{"login": login, "type": "User"}, "commit": map[string]any{"author": map[string]string{"name": "Full Name"}}}
	}
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("since") == "" {
			http.Error(w, "since missing", http.StatusBadRequest)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var out []commit
		switch page {
		case 1:
			for i := 0; i < 98; i++ {
				out = append(out, human("alice"))
			}
			out = append(out,
				commit{"author": map[string]string{"login": "dependabot[bot]", "type": "Bot"}, "commit": map[string]any{"author": map[string]string{"name": "dependabot"}}},
				commit{"author": nil, "commit": map[string]any{"author": map[string]string{"name": "renovate[bot]"}}})
		case 2:
			out = append(out, human("bob"), commit{"author": nil, "commit": map[string]any{"author": map[string]string{"name": "No Account"}}})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	got, err := c.CommitAuthors(context.Background(), "acme/app", time.Now().Add(-time.Hour), 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 || got[98] != "bob" || got[99] != "No Account" {
		t.Fatalf("len %d, tail %v", len(got), got[len(got)-2:])
	}
	capped, _ := c.CommitAuthors(context.Background(), "acme/app", time.Now(), 10)
	if len(capped) != 10 {
		t.Fatalf("max not applied: %d", len(capped))
	}
}

func TestOrgAdminsPaginates(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		n := 100
		if r.URL.Query().Get("page") == "2" {
			n = 3
		}
		var out []map[string]string
		for i := 0; i < n; i++ {
			out = append(out, map[string]string{"login": fmt.Sprintf("u%s-%d", r.URL.Query().Get("page"), i)})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	got, err := c.OrgAdmins(context.Background(), "acme")
	if err != nil || len(got) != 103 {
		t.Fatalf("%d %v", len(got), err)
	}
}

func TestBranchRuleTypes(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/repos/acme/app/rules/branches/release%2F1.x" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `[{"type":"pull_request"},{"type":"deletion"}]`)
	})
	got, err := c.BranchRuleTypes(context.Background(), "acme/app", "release/1.x")
	if err != nil || !reflect.DeepEqual(got, []string{"pull_request", "deletion"}) {
		t.Fatalf("%v %v", got, err)
	}
}
