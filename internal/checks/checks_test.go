package checks

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/ghclient"
	"github.com/ObaidAbdullah16/lifeline/internal/manifest"
	"github.com/ObaidAbdullah16/lifeline/internal/netcheck"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// fake is a programmable stand-in for GitHub, DoH and RDAP.
type fake struct {
	gh   map[string]any             // path -> JSON body (string = raw file content for /contents)
	dns  map[string]netcheck.Answer // "name|TYPE" -> answer
	rdap map[string]string          // domain -> expiration RFC3339
}

func (f *fake) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/dns"):
			key := r.URL.Query().Get("name") + "|" + r.URL.Query().Get("type")
			a := f.dns[key]
			_ = json.NewEncoder(w).Encode(a)
		case strings.HasPrefix(r.URL.Path, "/rdap/domain/"):
			d := strings.TrimPrefix(r.URL.Path, "/rdap/domain/")
			exp, ok := f.rdap[d]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"ldhName":%q,"events":[{"eventAction":"expiration","eventDate":%q}],
			  "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]]}]}`, d, exp)
		case strings.HasPrefix(r.URL.Path, "/gh/"):
			p := strings.TrimPrefix(r.URL.Path, "/gh")
			if r.URL.RawQuery != "" && !strings.Contains(p, "/commits") {
				p += "?" + r.URL.RawQuery
			}
			body, ok := f.gh[p]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if s, isStr := body.(string); isStr {
				_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(s))})
				return
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newEnv(t *testing.T, f *fake, m *manifest.Manifest) *Env {
	srv := f.server(t)
	if m == nil {
		m = &manifest.Manifest{Ignore: map[string]bool{}}
	}
	return &Env{
		Ctx:      context.Background(),
		GH:       &ghclient.Client{BaseURL: srv.URL + "/gh", HTTP: srv.Client()},
		DNS:      &netcheck.Resolver{Endpoints: []string{srv.URL + "/dns"}, HTTP: srv.Client()},
		RDAP:     &netcheck.RDAP{BaseURL: srv.URL + "/rdap", HTTP: srv.Client()},
		TLS:      &netcheck.TLSDialer{Timeout: time.Second},
		HTTP:     srv.Client(),
		Now:      now,
		Manifest: m,
	}
}

func find(t *testing.T, rep *Report, id string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result %s", id)
	return Result{}
}

func ans(ad bool, typ int, data ...string) netcheck.Answer {
	a := netcheck.Answer{AD: ad}
	for _, d := range data {
		a.Answer = append(a.Answer, struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		}{"x", typ, d})
	}
	return a
}

func TestDomainChecks(t *testing.T) {
	f := &fake{
		rdap: map[string]string{"example.org": now.Add(20 * 24 * time.Hour).Format(time.RFC3339)},
		dns: map[string]netcheck.Answer{
			"www.example.org|CAA":    {},
			"example.org|CAA":        ans(false, netcheck.TypeCAA, `0 issue "letsencrypt.org"`),
			"example.org|DS":         ans(true, netcheck.TypeDS, "2371 13 2 ABCD"),
			"example.org|SOA":        {Status: netcheck.RcodeServFail}, // bogus: validation fails
			"example.org|TXT":        ans(false, netcheck.TypeTXT, `"v=spf1 include:_spf.example.net" " -all"`),
			"_dmarc.example.org|TXT": ans(false, netcheck.TypeTXT, `"v=DMARC1; p=none; rua=mailto:d@example.org"`),
		},
	}
	e := newEnv(t, f, nil)
	tgt := Target{Domain: "www.example.org"}
	cases := map[string]Status{
		"LL-DOM-001": Fail, // 20 days left
		"LL-DOM-003": Pass,
		"LL-DOM-004": Fail, // signed but validation fails (SERVFAIL)
		"LL-DOM-005": Warn, // p=none
	}
	for _, c := range domainChecks {
		want, ok := cases[c.ID]
		if !ok {
			continue
		}
		got := runOne(e, tgt, c)
		if got.Status != want {
			t.Errorf("%s = %s (%s), want %s", c.ID, got.Status, got.Summary, want)
		}
	}
	if !strings.Contains(runOne(e, tgt, domainChecks[0]).Summary, "Example Registrar") {
		t.Error("registrar name missing")
	}
}

func TestDomainExpiryThresholdsAndNoRDAP(t *testing.T) {
	for daysLeft, want := range map[int]Status{200: Pass, 60: Warn, 10: Fail} {
		f := &fake{rdap: map[string]string{"example.net": now.Add(time.Duration(daysLeft) * 24 * time.Hour).Format(time.RFC3339)}}
		got := runOne(newEnv(t, f, nil), Target{Domain: "example.net"}, domainChecks[0])
		if got.Status != want {
			t.Errorf("%d days: %s, want %s", daysLeft, got.Status, want)
		}
	}
	got := runOne(newEnv(t, &fake{}, nil), Target{Domain: "example.zz"}, domainChecks[0])
	if got.Status != Skip {
		t.Errorf("no RDAP: %s", got.Status)
	}
}

func TestEmailAuthPassAndFail(t *testing.T) {
	f := &fake{dns: map[string]netcheck.Answer{
		"good.org|TXT":        ans(false, netcheck.TypeTXT, `"v=spf1 -all"`),
		"_dmarc.good.org|TXT": ans(false, netcheck.TypeTXT, `"v=DMARC1; p=reject"`),
	}}
	e := newEnv(t, f, nil)
	if got := runOne(e, Target{Domain: "good.org"}, domainChecks[4]); got.Status != Pass {
		t.Errorf("good.org: %s %s", got.Status, got.Summary)
	}
	e = newEnv(t, &fake{}, nil)
	if got := runOne(e, Target{Domain: "bad.org"}, domainChecks[4]); got.Status != Fail {
		t.Errorf("bad.org: %s", got.Status)
	}
}

func TestTLSCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	e := newEnv(t, &fake{}, nil)
	e.Now = time.Now()
	e.TLS = &netcheck.TLSDialer{Timeout: 2 * time.Second, Roots: pool, Addr: func(string) string { return srv.Listener.Addr().String() }}
	got := runOne(e, Target{Domain: "example.com"}, domainChecks[1])
	if got.Status != Pass {
		t.Fatalf("valid cert: %s %s", got.Status, got.Summary)
	}
	got = runOne(e, Target{Domain: "wrong-name.test"}, domainChecks[1])
	if got.Status != Fail || !strings.Contains(got.Summary, "does not verify") {
		t.Fatalf("name mismatch: %s %s", got.Status, got.Summary)
	}
	e.Now = srv.Certificate().NotAfter.Add(-3 * 24 * time.Hour)
	if got := runOne(e, Target{Domain: "example.com"}, domainChecks[1]); got.Status != Fail {
		t.Fatalf("3 days left: %s", got.Status)
	}
}

func ghRepo(ownerType string) map[string]any {
	return map[string]any{
		"full_name": "acme/app", "default_branch": "main", "homepage": "https://acme.example",
		"owner": map[string]any{"login": "acme", "type": ownerType},
	}
}

func TestAccessChecksOrg(t *testing.T) {
	tf := true
	f := &fake{gh: map[string]any{
		"/repos/acme/app": ghRepo("Organization"),
		"/orgs/acme/members?role=admin&per_page=100&page=1": []map[string]string{{"login": "a"}, {"login": "b"}},
		"/orgs/acme":                           map[string]any{"login": "acme", "two_factor_requirement_enabled": &tf},
		"/repos/acme/app/branches/main":        map[string]any{"protected": false},
		"/repos/acme/app/rules/branches/main":  []map[string]string{{"type": "pull_request"}, {"type": "non_fast_forward"}},
		"/repos/acme/app/contents/SECURITY.md": "Report to security@acme.example",
	}}
	e := newEnv(t, f, nil)
	tgt := Target{Repo: "acme/app"}
	want := map[string]Status{"LL-ACC-001": Pass, "LL-ACC-002": Pass, "LL-ACC-003": Pass, "LL-ACC-005": Pass}
	for _, c := range accessChecks {
		w, ok := want[c.ID]
		if !ok {
			continue
		}
		if got := runOne(e, tgt, c); got.Status != w {
			t.Errorf("%s = %s (%s), want %s", c.ID, got.Status, got.Summary, w)
		}
	}
}

func TestAccessChecksPersonalRepo(t *testing.T) {
	f := &fake{gh: map[string]any{
		"/repos/solo/tool":               ghRepo("User"),
		"/repos/solo/tool/branches/main": map[string]any{"protected": false},
	}}
	e := newEnv(t, f, nil)
	tgt := Target{Repo: "solo/tool"}
	if got := runOne(e, tgt, accessChecks[0]); got.Status != Fail {
		t.Errorf("personal owner: %s", got.Status)
	}
	if got := runOne(e, tgt, accessChecks[1]); got.Status != Skip {
		t.Errorf("2FA on personal: %s", got.Status)
	}
	if got := runOne(e, tgt, accessChecks[2]); got.Status != Fail {
		t.Errorf("unprotected: %s", got.Status)
	}
	if got := runOne(e, tgt, accessChecks[4]); got.Status != Fail {
		t.Errorf("no security contact: %s", got.Status)
	}
}

func TestBusFactor(t *testing.T) {
	cases := []struct {
		authors []string
		want    int
	}{
		{[]string{"a", "a", "a", "a", "a", "a", "a", "a", "a", "b"}, 1},
		{[]string{"a", "a", "a", "a", "b", "b", "b", "c", "d", "e"}, 3},
		{[]string{"a", "b", "a", "b"}, 2},
	}
	for _, c := range cases {
		if got, _ := BusFactor(c.authors); got != c.want {
			t.Errorf("BusFactor(%v) = %d, want %d", c.authors, got, c.want)
		}
	}
}

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const sha = "0123456789abcdef0123456789abcdef01234567"

func TestCIChecksGoodRepo(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		".github/workflows/ci.yml": `on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + sha + ` # v7
      - uses: ./.github/actions/local
      - run: make test
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@` + sha + `
        with:
          role-to-assume: arn:aws:iam::1:role/x
`,
		".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n",
	})
	e := newEnv(t, &fake{}, nil)
	for _, c := range ciChecks {
		got := runOne(e, Target{LocalPath: dir}, c)
		if got.Status != Pass {
			t.Errorf("%s = %s (%s)", c.ID, got.Status, got.Summary)
		}
	}
}

func TestCIChecksBadRepo(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		".github/workflows/pr.yml": `on: pull_request_target
permissions: write-all
env:
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@` + sha + `
      - uses: other/action@main
      - uses: third/action@v1
`,
	})
	e := newEnv(t, &fake{}, nil)
	want := map[string]Status{"LL-CI-001": Fail, "LL-CI-002": Fail, "LL-CI-003": Fail, "LL-CI-004": Fail, "LL-CI-005": Fail}
	for _, c := range ciChecks {
		got := runOne(e, Target{LocalPath: dir}, c)
		if got.Status != want[c.ID] {
			t.Errorf("%s = %s (%s), want %s", c.ID, got.Status, got.Summary, want[c.ID])
		}
		if c.ID == "LL-CI-001" && (got.Score != 2 || got.Location != ".github/workflows/pr.yml") {
			t.Errorf("pinned score/location = %d %q", got.Score, got.Location)
		}
	}
}

func TestCIWorkflowsFromAPI(t *testing.T) {
	f := &fake{gh: map[string]any{
		"/repos/acme/app/contents/.github/workflows":        []map[string]string{{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"}},
		"/repos/acme/app/contents/.github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v7\n",
	}}
	e := newEnv(t, f, nil)
	got := runOne(e, Target{Repo: "acme/app"}, ciChecks[0])
	if got.Status != Fail || !strings.Contains(got.Summary, "0 of 1") {
		t.Fatalf("%s %s", got.Status, got.Summary)
	}
}

func TestBackupAndCostChecks(t *testing.T) {
	m, err := manifest.Parse(`project: demo
backups:
  - name: db
    what: postgres
    location: s3 in another account
    isolated: true
    last_restore_test: 2026-09-01
  - name: files
    what: uploads
    location: same bucket versioning
    last_restore_test: 2026-06-01
cost:
  monthly_spend_usd: 100
  credits_remaining_usd: 1000
  credits_expire: 2027-06-30
  budget_alerts: yes
`)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, &fake{}, m)
	want := map[string]Status{
		"LL-BAK-001": Pass, "LL-BAK-002": Warn, "LL-BAK-003": Warn,
		// $1000 credits at $100/month would last ~304 days, but they expire in ~249 days -> still >= 180: pass
		"LL-COST-001": Pass,
		"LL-COST-002": Pass,
	}
	for _, c := range append(append([]Check{}, backupChecks...), costChecks...) {
		got := runOne(e, Target{}, c)
		if got.Status != want[c.ID] {
			t.Errorf("%s = %s (%s), want %s", c.ID, got.Status, got.Summary, want[c.ID])
		}
	}
}

func TestRunwayDays(t *testing.T) {
	// $1000 credits at $100/month = ~304 days, but credits expire in 30 days -> only ~30 days usable
	d := RunwayDays(100, 1000, 0, now.Add(30*24*time.Hour), now)
	if d < 29 || d > 31 {
		t.Fatalf("runway = %.1f", d)
	}
	if d := RunwayDays(100, 0, 600, time.Time{}, now); d < 182 || d > 183 {
		t.Fatalf("cash runway = %.1f", d)
	}
}

func TestManifestMissingSkipsAndIgnore(t *testing.T) {
	e := newEnv(t, &fake{}, nil)
	if got := runOne(e, Target{}, backupChecks[0]); got.Status != Skip {
		t.Fatalf("no manifest: %s", got.Status)
	}
	m := &manifest.Manifest{Found: true, Ignore: map[string]bool{"LL-BAK-001": true}}
	e = newEnv(t, &fake{}, m)
	if got := runOne(e, Target{}, backupChecks[0]); got.Status != Skip || !strings.Contains(got.Summary, "ignored") {
		t.Fatalf("ignored: %s %s", got.Status, got.Summary)
	}
}

func TestAggregate(t *testing.T) {
	rs := []Result{
		{Weight: 10, Score: 10},
		{Weight: 10, Score: 0},
		{Weight: 5, Score: -1},
	}
	s, cov := Aggregate(rs)
	if s != 5 || cov != 0.8 {
		t.Fatalf("score %.1f coverage %.2f", s, cov)
	}
}

func TestRunEndToEndWithHomepageDomain(t *testing.T) {
	f := &fake{
		gh: map[string]any{
			"/repos/acme/app": ghRepo("User"),
		},
		rdap: map[string]string{"acme.example": now.Add(400 * 24 * time.Hour).Format(time.RFC3339)},
	}
	e := newEnv(t, f, nil)
	rep := Run(e, Target{Repo: "acme/app"}, "test")
	if rep.Domain != "acme.example" {
		t.Fatalf("domain from homepage = %q", rep.Domain)
	}
	if got := find(t, rep, "LL-DOM-001"); got.Status != Pass {
		t.Fatalf("expiry: %s %s", got.Status, got.Summary)
	}
	if rep.Score <= 0 || rep.Score > 10 || rep.Coverage <= 0 {
		t.Fatalf("score %.1f coverage %.2f", rep.Score, rep.Coverage)
	}
	if _, ok := rep.Categories[CatDomain]; !ok {
		t.Fatal("domain category missing")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.org/docs": "example.org",
		"example.org":              "example.org",
		"http://a.b.example:8080":  "a.b.example",
		"https://user.github.io/x": "",
		"https://GitHub.com/acme":  "",
		"docs.github.com":          "",
		"https://mygithub.io":      "mygithub.io", // a different domain, not GitHub Pages
		"notgithub.com/path":       "notgithub.com",
		"":                         "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApexForTwoLabelSuffixAndMissingExpiry(t *testing.T) {
	// The .uk registry answers for example.co.uk but (in this fake) publishes no expiry date.
	f := &fake{
		rdap: map[string]string{"example.co.uk": ""},
		dns: map[string]netcheck.Answer{
			"example.co.uk|DS":         ans(true, netcheck.TypeDS, "1 13 2 AB"),
			"example.co.uk|SOA":        ans(true, 6, "ns.example.co.uk. hostmaster.example.co.uk. 1 2 3 4 5"),
			"example.co.uk|TXT":        ans(false, netcheck.TypeTXT, `"v=spf1 -all"`),
			"_dmarc.example.co.uk|TXT": ans(false, netcheck.TypeTXT, `"v=DMARC1; p=reject"`),
		},
	}
	e := newEnv(t, f, nil)
	tgt := Target{Domain: "www.example.co.uk"}
	if got := runOne(e, tgt, domainChecks[0]); got.Status != Skip || !strings.Contains(got.Summary, "no expiry date") {
		t.Errorf("missing expiry: %s %s", got.Status, got.Summary)
	}
	if got := e.Apex("www.example.co.uk"); got != "example.co.uk" {
		t.Errorf("apex = %q", got)
	}
	if got := runOne(e, tgt, domainChecks[3]); got.Status != Pass {
		t.Errorf("DNSSEC should be checked on example.co.uk, not co.uk: %s %s", got.Status, got.Summary)
	}
	if got := runOne(e, tgt, domainChecks[4]); got.Status != Pass {
		t.Errorf("email auth on example.co.uk: %s %s", got.Status, got.Summary)
	}
	// Without any RDAP data the guess still knows co.uk.
	if got := newEnv(t, &fake{}, nil).Apex("a.b.example.co.uk"); got != "example.co.uk" {
		t.Errorf("guessed apex = %q", got)
	}
}

func TestEmailAuthMisconfigurations(t *testing.T) {
	for name, tc := range map[string]struct {
		spf, dmarc []string
		want       string
	}{
		"plus all":      {[]string{`"v=spf1 include:mail.example +all"`}, []string{`"v=DMARC1; p=reject"`}, "+all"},
		"bare all":      {[]string{`"v=spf1 a mx all"`}, []string{`"v=DMARC1; p=reject"`}, "+all"},
		"two spf":       {[]string{`"v=spf1 -all"`, `"v=spf1 include:x -all"`}, []string{`"v=DMARC1; p=reject"`}, "2 SPF records"},
		"two dmarc":     {[]string{`"v=spf1 -all"`}, []string{`"v=DMARC1; p=reject"`, `"v=DMARC1; p=none"`}, "2 DMARC records"},
		"dmarc no p":    {[]string{`"v=spf1 -all"`}, []string{`"v=DMARC1; rua=mailto:d@x.org"`}, "no p= tag"},
		"spf10 is junk": {[]string{`"v=spf10 -all"`}, []string{`"v=DMARC1; p=reject"`}, "DMARC present but no SPF"},
	} {
		f := &fake{dns: map[string]netcheck.Answer{
			"x.org|TXT":        ans(false, netcheck.TypeTXT, tc.spf...),
			"_dmarc.x.org|TXT": ans(false, netcheck.TypeTXT, tc.dmarc...),
		}}
		got := runOne(newEnv(t, f, nil), Target{Domain: "x.org"}, domainChecks[4])
		if got.Status != Warn || !strings.Contains(got.Summary, tc.want) {
			t.Errorf("%s: %s %q", name, got.Status, got.Summary)
		}
	}
}

func TestSingleVisibleOwner(t *testing.T) {
	one := []map[string]string{{"login": "a"}}
	// Without an owner's view (no 2FA field) private owners are invisible: warn, do not fail.
	f := &fake{gh: map[string]any{
		"/repos/acme/app": ghRepo("Organization"),
		"/orgs/acme/members?role=admin&per_page=100&page=1": one,
		"/orgs/acme": map[string]any{"login": "acme"},
	}}
	if got := runOne(newEnv(t, f, nil), Target{Repo: "acme/app"}, accessChecks[0]); got.Status != Warn || !strings.Contains(got.Summary, "public memberships only") {
		t.Errorf("public view: %s %s", got.Status, got.Summary)
	}
	// An owner's token sees everything: one owner is a real single point of failure.
	off := false
	f.gh["/orgs/acme"] = map[string]any{"login": "acme", "two_factor_requirement_enabled": &off}
	if got := runOne(newEnv(t, f, nil), Target{Repo: "acme/app"}, accessChecks[0]); got.Status != Fail {
		t.Errorf("owner view: %s %s", got.Status, got.Summary)
	}
}

func TestRateLimitAndBadTokenAreErrorsNotSkips(t *testing.T) {
	for _, err := range []error{fmt.Errorf("wrapped: %w", ghclient.ErrRateLimited), ghclient.ErrBadToken} {
		r := errResult(err)
		if r.Status != Error || !strings.Contains(r.Summary, "GITHUB_TOKEN") {
			t.Fatalf("%v: %s %s", err, r.Status, r.Summary)
		}
	}
	if r := errResult(fmt.Errorf("x: %w", ghclient.ErrForbidden)); r.Status != Skip {
		t.Fatalf("forbidden: %s", r.Status)
	}
}

func TestSecurityContactFromLocalPath(t *testing.T) {
	dir := writeRepo(t, map[string]string{".github/SECURITY.md": "Report privately."})
	got := runOne(newEnv(t, &fake{}, nil), Target{LocalPath: dir}, accessChecks[4])
	if got.Status != Pass {
		t.Fatalf("a local checkout is enough for LL-ACC-005: %s %s", got.Status, got.Summary)
	}
}

func TestPwnRequestVariants(t *testing.T) {
	bad := map[string]string{
		"issue_comment + gh pr checkout": `on: issue_comment
jobs:
  bot:
    runs-on: x
    steps:
      - uses: actions/checkout@v7
      - run: gh pr checkout ${{ github.event.issue.number }} && make test
`,
		"pull_request_target + git fetch": `on: pull_request_target
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/checkout@v7
      - run: |
          git fetch origin pull/${{ github.event.number }}/head:pr
          git checkout pr
`,
		"merge commit": `on:
  pull_request_target:
    types: [labeled]
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.merge_commit_sha }}
`,
		"head from an earlier step": `on: issue_comment
jobs:
  t:
    runs-on: x
    steps:
      - id: pr
        run: echo "head_sha=$(gh pr view 1 --json headRefOid -q .headRefOid)" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v7
        with:
          ref: ${{ steps.pr.outputs.head_sha }}
`,
		"fork repository": `on: pull_request_target
jobs:
  t:
    runs-on: x
    steps:
      - uses: actions/checkout@v7
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
`,
	}
	for name, wf := range bad {
		dir := writeRepo(t, map[string]string{".github/workflows/x.yml": wf})
		got := runOne(newEnv(t, &fake{}, nil), Target{LocalPath: dir}, ciChecks[2])
		if got.Status != Fail {
			t.Errorf("%s: %s %s", name, got.Status, got.Summary)
		}
	}
	safe := map[string]string{
		"target checks out the base": "on: pull_request_target\njobs:\n  label:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v7\n      - run: ./label.sh\n",
		"comment bot without code":   "on: issue_comment\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: gh issue comment 1 --body hi\n",
		"plain pull_request":         "on: pull_request\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: gh pr checkout 1\n",
	}
	for name, wf := range safe {
		dir := writeRepo(t, map[string]string{".github/workflows/x.yml": wf})
		got := runOne(newEnv(t, &fake{}, nil), Target{LocalPath: dir}, ciChecks[2])
		if got.Status != Pass {
			t.Errorf("%s: %s %s", name, got.Status, got.Summary)
		}
	}
}

func TestUnparsedWorkflowIsNotACleanPass(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		".github/workflows/ok.yml":     "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
		".github/workflows/broken.yml": "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n   oops: [\n",
	})
	e := newEnv(t, &fake{}, nil)
	got := runOne(e, Target{LocalPath: dir}, ciChecks[2])
	if got.Status != Warn || got.Location != ".github/workflows/broken.yml" || !strings.Contains(strings.Join(got.Details, " "), "review it by hand") {
		t.Fatalf("%s %s %v %q", got.Status, got.Summary, got.Details, got.Location)
	}
	if got.Score != 5 {
		t.Fatalf("score %d", got.Score)
	}
}

func TestIgnoreWildcard(t *testing.T) {
	m := &manifest.Manifest{Found: true, Ignore: map[string]bool{"LL-BAK-*": true}}
	e := newEnv(t, &fake{}, m)
	for _, c := range backupChecks {
		if got := runOne(e, Target{}, c); got.Status != Skip {
			t.Errorf("%s not ignored: %s", c.ID, got.Status)
		}
	}
	if got := runOne(e, Target{}, costChecks[0]); got.Status == Skip && strings.Contains(got.Summary, "ignored") {
		t.Error("LL-BAK-* must not ignore cost checks")
	}
}

func TestRestoreDateInTheFuture(t *testing.T) {
	m, err := manifest.Parse("backups:\n  - name: db\n    isolated: true\n    last_restore_test: 2062-10-01\n")
	if err != nil {
		t.Fatal(err)
	}
	got := runOne(newEnv(t, &fake{}, m), Target{}, backupChecks[1])
	if got.Status != Warn || !strings.Contains(strings.Join(got.Details, " "), "future") {
		t.Fatalf("%s %s %v", got.Status, got.Summary, got.Details)
	}
}

func TestDNSSECWithUnsignedCDN(t *testing.T) {
	// The apex is signed and validates; www is a CNAME to an unsigned CDN, so
	// answers for www are "insecure" (AD=false). That is not a broken chain.
	f := &fake{dns: map[string]netcheck.Answer{
		"example.org|DS":    ans(true, netcheck.TypeDS, "2371 13 2 ABCD"),
		"example.org|SOA":   ans(true, 6, "ns1.example.org. admin.example.org. 1 2 3 4 5"),
		"www.example.org|A": ans(false, netcheck.TypeCNAME, "example.cdn-provider.net."),
	}}
	got := runOne(newEnv(t, f, nil), Target{Domain: "www.example.org"}, domainChecks[3])
	if got.Status != Pass {
		t.Fatalf("%s %s", got.Status, got.Summary)
	}
	// Signed, resolver answers but does not set AD: warn, do not fail.
	f.dns["example.org|SOA"] = ans(false, 6, "ns1.example.org. admin.example.org. 1 2 3 4 5")
	if got := runOne(newEnv(t, f, nil), Target{Domain: "www.example.org"}, domainChecks[3]); got.Status != Warn {
		t.Fatalf("no AD: %s %s", got.Status, got.Summary)
	}
}

func TestPinnedScoreNeverFullUnlessAllPinned(t *testing.T) {
	steps := ""
	for i := 0; i < 19; i++ {
		steps += "      - uses: vendor/a" + fmt.Sprint(i) + "@" + sha + "\n"
	}
	steps += "      - uses: vendor/last@v1\n"
	dir := writeRepo(t, map[string]string{".github/workflows/ci.yml": "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n" + steps})
	got := runOne(newEnv(t, &fake{}, nil), Target{LocalPath: dir}, ciChecks[0])
	if got.Status != Warn || got.Score != 9 {
		t.Fatalf("19 of 20 pinned: %s %d", got.Status, got.Score)
	}
}

func dkimCheck(t *testing.T) Check {
	t.Helper()
	for _, c := range domainChecks {
		if c.ID == "LL-DOM-006" {
			return c
		}
	}
	t.Fatal("no LL-DOM-006")
	return Check{}
}

func spfLookupCheck(t *testing.T) Check {
	t.Helper()
	for _, c := range domainChecks {
		if c.ID == "LL-DOM-007" {
			return c
		}
	}
	t.Fatal("no LL-DOM-007")
	return Check{}
}

func TestDKIM(t *testing.T) {
	sending := ans(false, netcheck.TypeTXT, `"v=spf1 include:_spf.google.com ~all"`)
	cases := map[string]struct {
		dns      map[string]netcheck.Answer
		selector []string
		want     Status
		text     string
	}{
		"google key": {map[string]netcheck.Answer{"x.org|TXT": sending,
			"google._domainkey.x.org|TXT": ans(false, netcheck.TypeTXT, `"v=DKIM1; k=rsa; p=MIIBIjANBgkq"`)}, nil, Pass, "google"},
		"custom selector from manifest": {map[string]netcheck.Answer{"x.org|TXT": sending,
			"acme2026._domainkey.x.org|TXT": ans(false, netcheck.TypeTXT, `"k=rsa; p=MIGfMA0GCSq"`)}, []string{"acme2026"}, Pass, "acme2026"},
		"revoked only": {map[string]netcheck.Answer{"x.org|TXT": sending,
			"selector1._domainkey.x.org|TXT": ans(false, netcheck.TypeTXT, `"v=DKIM1; p="`)}, nil, Warn, "revoked"},
		"none":                 {map[string]netcheck.Answer{"x.org|TXT": sending}, nil, Warn, "dkim_selectors"},
		"domain sends no mail": {map[string]netcheck.Answer{"x.org|TXT": ans(false, netcheck.TypeTXT, `"v=spf1 -all"`)}, nil, Skip, "sends no email"},
	}
	for name, tc := range cases {
		m := &manifest.Manifest{Ignore: map[string]bool{}, DKIMSelectors: tc.selector}
		got := runOne(newEnv(t, &fake{dns: tc.dns}, m), Target{Domain: "x.org"}, dkimCheck(t))
		if got.Status != tc.want || !strings.Contains(got.Summary, tc.text) {
			t.Errorf("%s: %s %q", name, got.Status, got.Summary)
		}
	}
}

func TestSPFLookups(t *testing.T) {
	inc := func(n int) string {
		parts := []string{"v=spf1"}
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("include:s%d.example.net", i))
		}
		return `"` + strings.Join(append(parts, "-all"), " ") + `"`
	}
	for name, tc := range map[string]struct {
		spf   string
		inner string // SPF of every included domain
		want  Status
		count string
	}{
		"few":           {inc(3), `"v=spf1 ip4:192.0.2.0/24 -all"`, Pass, "needs 3 of"},
		"nested a/mx":   {inc(3), `"v=spf1 a mx -all"`, Warn, "needs 9 of"},
		"over the edge": {inc(4), `"v=spf1 a mx include:deep.example.net -all"`, Fail, "permerror"},
	} {
		dns := map[string]netcheck.Answer{"x.org|TXT": ans(false, netcheck.TypeTXT, tc.spf),
			"deep.example.net|TXT": ans(false, netcheck.TypeTXT, `"v=spf1 ip4:198.51.100.0/24 -all"`)}
		for i := 0; i < 5; i++ {
			dns[fmt.Sprintf("s%d.example.net|TXT", i)] = ans(false, netcheck.TypeTXT, tc.inner)
		}
		got := runOne(newEnv(t, &fake{dns: dns}, nil), Target{Domain: "x.org"}, spfLookupCheck(t))
		if got.Status != tc.want || !strings.Contains(got.Summary, tc.count) {
			t.Errorf("%s: %s %q", name, got.Status, got.Summary)
		}
	}
	// a loop (a includes b includes a) must terminate
	loop := map[string]netcheck.Answer{
		"x.org|TXT":     ans(false, netcheck.TypeTXT, `"v=spf1 include:a.example -all"`),
		"a.example|TXT": ans(false, netcheck.TypeTXT, `"v=spf1 include:x.org -all"`),
	}
	if got := runOne(newEnv(t, &fake{dns: loop}, nil), Target{Domain: "x.org"}, spfLookupCheck(t)); got.Status != Pass {
		t.Errorf("loop: %s %q", got.Status, got.Summary)
	}
	if got := runOne(newEnv(t, &fake{}, nil), Target{Domain: "x.org"}, spfLookupCheck(t)); got.Status != Skip {
		t.Errorf("no spf: %s", got.Status)
	}
}
