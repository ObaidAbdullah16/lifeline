// Package checks contains Lifeline's resilience checks and the runner that
// turns their results into a score.
package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/ghclient"
	"github.com/ObaidAbdullah16/lifeline/internal/manifest"
	"github.com/ObaidAbdullah16/lifeline/internal/netcheck"
	"github.com/ObaidAbdullah16/lifeline/internal/workflows"
)

// Status of one check.
type Status string

// Possible statuses.
const (
	Pass  Status = "pass"
	Warn  Status = "warn"
	Fail  Status = "fail"
	Skip  Status = "skip"
	Error Status = "error"
)

// Category names.
const (
	CatDomain = "Domain & TLS"
	CatAccess = "Access & bus factor"
	CatCI     = "CI hygiene"
	CatBackup = "Backup independence"
	CatCost   = "Cost runway"
)

// Categories in report order.
var Categories = []string{CatDomain, CatAccess, CatCI, CatBackup, CatCost}

// Result is the outcome of one check.
type Result struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Status      Status   `json:"status"`
	Score       int      `json:"score"` // 0-10, -1 when skipped
	Weight      int      `json:"weight"`
	Summary     string   `json:"summary"`
	Details     []string `json:"details,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Location    string   `json:"location,omitempty"` // file the finding points at (for SARIF)
}

// Target is what to scan.
type Target struct {
	Repo      string // owner/name (optional)
	Domain    string // optional; defaults to manifest domain or repo homepage
	LocalPath string // local checkout root (optional)
}

// Env carries clients and lazily loaded data shared by checks.
type Env struct {
	Ctx      context.Context
	GH       *ghclient.Client
	DNS      *netcheck.Resolver
	RDAP     *netcheck.RDAP
	TLS      *netcheck.TLSDialer
	HTTP     *http.Client
	Now      time.Time
	Manifest *manifest.Manifest

	repoMeta     *ghclient.Repo
	repoErr      error
	repoLoaded   bool
	wf           []workflows.File
	wfErr        error
	wfLoaded     bool
	registration *netcheck.Registration
	regErr       error
	regLoaded    bool
	org          *ghclient.Org
	orgErr       error
	orgLoaded    bool
}

// NewEnv returns an Env with real network clients.
func NewEnv(ctx context.Context, m *manifest.Manifest) *Env {
	return &Env{
		Ctx:      ctx,
		GH:       ghclient.New(),
		DNS:      netcheck.NewResolver(),
		RDAP:     netcheck.NewRDAP(),
		TLS:      &netcheck.TLSDialer{},
		HTTP:     &http.Client{Timeout: 10 * time.Second},
		Now:      time.Now().UTC(),
		Manifest: m,
	}
}

// Repo returns repository metadata (cached).
func (e *Env) Repo(t Target) (*ghclient.Repo, error) {
	if !e.repoLoaded {
		e.repoLoaded = true
		if t.Repo == "" {
			e.repoErr = errors.New("no --repo given")
		} else {
			e.repoMeta, e.repoErr = e.GH.GetRepo(e.Ctx, t.Repo)
		}
	}
	return e.repoMeta, e.repoErr
}

// Org returns organisation metadata (cached).
func (e *Env) Org(login string) (*ghclient.Org, error) {
	if !e.orgLoaded {
		e.orgLoaded = true
		e.org, e.orgErr = e.GH.GetOrg(e.Ctx, login)
	}
	return e.org, e.orgErr
}

// Workflows loads workflow files from the local checkout or the GitHub API (cached).
func (e *Env) Workflows(t Target) ([]workflows.File, error) {
	if e.wfLoaded {
		return e.wf, e.wfErr
	}
	e.wfLoaded = true
	if t.LocalPath != "" {
		e.wf, e.wfErr = workflows.LoadDir(filepath.Join(t.LocalPath, ".github", "workflows"))
		return e.wf, e.wfErr
	}
	if t.Repo == "" {
		e.wfErr = errors.New("no repository to read workflows from")
		return nil, e.wfErr
	}
	entries, err := e.GH.ListDir(e.Ctx, t.Repo, ".github/workflows")
	if err != nil {
		e.wfErr = err
		return nil, err
	}
	for _, ent := range entries {
		if ent.Type != "file" || !(strings.HasSuffix(ent.Name, ".yml") || strings.HasSuffix(ent.Name, ".yaml")) {
			continue
		}
		text, err := e.GH.FileText(e.Ctx, t.Repo, ent.Path)
		if err != nil {
			e.wfErr = err
			return nil, err
		}
		e.wf = append(e.wf, workflows.Parse(ent.Path, text))
	}
	sort.Slice(e.wf, func(i, j int) bool { return e.wf[i].Path < e.wf[j].Path })
	return e.wf, nil
}

// RepoFile returns a file from the local checkout or the API. ok=false when missing.
func (e *Env) RepoFile(t Target, path string) (string, bool) {
	if t.LocalPath != "" {
		b, err := os.ReadFile(filepath.Join(t.LocalPath, filepath.FromSlash(path)))
		if err == nil {
			return string(b), true
		}
		return "", false
	}
	if t.Repo == "" {
		return "", false
	}
	text, err := e.GH.FileText(e.Ctx, t.Repo, path)
	if err != nil {
		return "", false
	}
	return text, true
}

// Registration returns RDAP data for the target domain (cached).
func (e *Env) Registration(domain string) (*netcheck.Registration, error) {
	if !e.regLoaded {
		e.regLoaded = true
		e.registration, e.regErr = e.RDAP.Lookup(e.Ctx, domain)
	}
	return e.registration, e.regErr
}

// Apex returns the registrable domain: the name RDAP answered for when
// available (even if the record lacked an expiry date), otherwise a guess
// that knows common two-label suffixes such as co.uk.
func (e *Env) Apex(domain string) string {
	if reg, _ := e.Registration(domain); reg != nil && reg.Domain != "" {
		return reg.Domain
	}
	return netcheck.GuessApex(domain)
}

// Requirement says which input a check needs.
type Requirement int

// Requirements.
const (
	NeedsDomain     Requirement = iota
	NeedsRepo                   // GitHub API data (owners, branch protection, commits)
	NeedsRepoOrPath             // repository files, from a local checkout or the API
	NeedsManifest
)

// Check is one registered check.
type Check struct {
	ID          string
	Category    string
	Title       string
	Weight      int
	Needs       Requirement
	Remediation string
	Run         func(e *Env, t Target) Result
}

// All returns every check in report order.
func All() []Check {
	all := append([]Check{}, domainChecks...)
	all = append(all, accessChecks...)
	all = append(all, ciChecks...)
	all = append(all, backupChecks...)
	all = append(all, costChecks...)
	return all
}

// Report is the result of a scan.
type Report struct {
	Tool        string             `json:"tool"`
	Version     string             `json:"version"`
	GeneratedAt time.Time          `json:"generated_at"`
	Repo        string             `json:"repository,omitempty"`
	Domain      string             `json:"domain,omitempty"`
	Score       float64            `json:"score"`    // 0-10
	Coverage    float64            `json:"coverage"` // share of checks that could run (by weight)
	Categories  map[string]float64 `json:"categories"`
	Results     []Result           `json:"results"`
	Previous    *float64           `json:"previous_score,omitempty"`
	Delta       *float64           `json:"delta,omitempty"`
}

// Run executes every check and computes the score.
func Run(e *Env, t Target, version string) *Report {
	if t.Domain == "" && e.Manifest != nil {
		t.Domain = e.Manifest.Domain
	}
	if t.Domain == "" && t.Repo != "" {
		if r, err := e.Repo(t); err == nil {
			t.Domain = hostOf(r.Homepage)
		}
	}
	t.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(t.Domain)), ".")

	rep := &Report{Tool: "lifeline", Version: version, GeneratedAt: e.Now, Repo: t.Repo, Domain: t.Domain, Categories: map[string]float64{}}
	for _, c := range All() {
		res := runOne(e, t, c)
		rep.Results = append(rep.Results, res)
	}
	rep.Score, rep.Coverage = Aggregate(rep.Results)
	for _, cat := range Categories {
		var rs []Result
		for _, r := range rep.Results {
			if r.Category == cat {
				rs = append(rs, r)
			}
		}
		if s, cov := Aggregate(rs); cov > 0 {
			rep.Categories[cat] = s
		}
	}
	return rep
}

func runOne(e *Env, t Target, c Check) (res Result) {
	base := Result{ID: c.ID, Category: c.Category, Title: c.Title, Weight: c.Weight, Remediation: c.Remediation, Score: -1}
	skip := func(why string) Result {
		base.Status, base.Summary = Skip, why
		return base
	}
	if e.Manifest.Ignores(c.ID) {
		return skip("ignored in lifeline.yml")
	}
	switch c.Needs {
	case NeedsDomain:
		if t.Domain == "" {
			return skip("no domain (pass --domain, set `domain:` in lifeline.yml, or a repo homepage)")
		}
	case NeedsRepo:
		if t.Repo == "" {
			return skip("no repository (pass --repo owner/name)")
		}
	case NeedsRepoOrPath:
		if t.Repo == "" && t.LocalPath == "" {
			return skip("no repository or local path")
		}
	case NeedsManifest:
		if e.Manifest == nil || !e.Manifest.Found {
			return skip("no lifeline.yml (see examples/lifeline.yml) - this check needs facts only you know")
		}
	}
	defer func() {
		if r := recover(); r != nil {
			res = base
			res.Status, res.Summary = Error, fmt.Sprintf("internal error: %v", r)
		}
	}()
	out := c.Run(e, t)
	out.ID, out.Category, out.Title, out.Weight = c.ID, c.Category, c.Title, c.Weight
	if out.Remediation == "" {
		out.Remediation = c.Remediation
	}
	if out.Score == 0 && out.Status != Fail {
		out.Score = statusScore(out.Status)
	}
	if out.Status == Skip || out.Status == Error {
		out.Score = -1
	}
	return out
}

func statusScore(s Status) int {
	switch s {
	case Pass:
		return 10
	case Warn:
		return 5
	case Fail:
		return 0
	}
	return -1
}

// Aggregate returns the weighted 0-10 score of results and the weight coverage.
func Aggregate(rs []Result) (score, coverage float64) {
	var num, den, total float64
	for _, r := range rs {
		total += float64(r.Weight)
		if r.Score < 0 {
			continue
		}
		num += float64(r.Score * r.Weight)
		den += float64(r.Weight)
	}
	if den == 0 {
		return 0, 0
	}
	return math.Round(num/den*10) / 10, math.Round(den/total*100) / 100
}

func hostOf(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	u = strings.SplitN(strings.SplitN(u, "://", 2)[1], "/", 2)[0]
	u = strings.ToLower(strings.SplitN(u, ":", 2)[0])
	for _, shared := range []string{"github.io", "github.com"} {
		if u == shared || strings.HasSuffix(u, "."+shared) {
			return "" // shared platform domain: the project does not control it
		}
	}
	return u
}

// helpers used by the check files

func result(s Status, summary string, details ...string) Result {
	return Result{Status: s, Summary: summary, Details: details}
}

func days(d time.Duration) int { return int(math.Floor(d.Hours() / 24)) }

func errResult(err error) Result {
	if errors.Is(err, ghclient.ErrRateLimited) {
		return result(Error, "GitHub API rate limit reached - set GITHUB_TOKEN and run again")
	}
	if errors.Is(err, ghclient.ErrBadToken) {
		return result(Error, "GitHub rejected the token (expired or revoked?) - fix GITHUB_TOKEN or unset it")
	}
	if errors.Is(err, ghclient.ErrForbidden) {
		return result(Skip, "not visible with the current token: "+shortErr(err))
	}
	return result(Error, shortErr(err))
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
