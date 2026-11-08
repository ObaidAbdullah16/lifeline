// Package workflows reads GitHub Actions workflow files and answers the
// questions Lifeline's CI-hygiene checks ask about them.
package workflows

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ObaidAbdullah16/lifeline/internal/yamlite"
)

// File is one parsed workflow.
type File struct {
	Path string
	Raw  string
	Doc  map[string]any
	Err  error
}

// Parse parses workflow text.
func Parse(path, raw string) File {
	doc, err := yamlite.ParseMap(raw)
	return File{Path: path, Raw: raw, Doc: doc, Err: err}
}

// LoadDir reads *.yml / *.yaml from dir (normally <repo>/.github/workflows).
func LoadDir(dir string) ([]File, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []File
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, Parse(filepath.ToSlash(filepath.Join(".github/workflows", n)), string(b)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Triggers returns the event names in `on:`.
func (f File) Triggers() []string {
	var out []string
	switch on := f.Doc["on"].(type) {
	case string:
		out = []string{on}
	case []any:
		for _, x := range on {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		for k := range on {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// HasTrigger reports whether any of the given events triggers the workflow.
func (f File) HasTrigger(names ...string) bool {
	for _, t := range f.Triggers() {
		for _, n := range names {
			if t == n {
				return true
			}
		}
	}
	return false
}

// Job is a job definition with its id.
type Job struct {
	ID  string
	Def map[string]any
}

// Jobs returns jobs sorted by id.
func (f File) Jobs() []Job {
	m, _ := f.Doc["jobs"].(map[string]any)
	var out []Job
	for id, v := range m {
		if def, ok := v.(map[string]any); ok {
			out = append(out, Job{ID: id, Def: def})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Steps returns the job's steps.
func (j Job) Steps() []map[string]any {
	s, _ := j.Def["steps"].([]any)
	var out []map[string]any
	for _, x := range s {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Str returns m[key] as a string ("" if missing or not a string).
func Str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// Uses is one `uses:` reference.
type Uses struct {
	Ref    string // full reference as written
	Target string // owner/repo[/path]
	Ver    string // part after @ ("" if none)
	Job    string
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Pinned reports whether the reference is immutable (commit SHA, image digest or local path).
func (u Uses) Pinned() bool {
	switch {
	case strings.HasPrefix(u.Ref, "./"), strings.HasPrefix(u.Ref, "$/"):
		return true
	case strings.HasPrefix(u.Ref, "docker://"):
		return strings.Contains(u.Ref, "@sha256:")
	}
	return shaRe.MatchString(u.Ver)
}

// FirstParty reports whether the action is maintained by GitHub itself.
func (u Uses) FirstParty() bool {
	owner := strings.ToLower(strings.SplitN(u.Target, "/", 2)[0])
	return owner == "actions" || owner == "github"
}

// Local reports whether the reference points inside the same repository.
func (u Uses) Local() bool {
	return strings.HasPrefix(u.Ref, "./") || strings.HasPrefix(u.Ref, "$/")
}

// AllUses lists every action and reusable-workflow reference.
func (f File) AllUses() []Uses {
	var out []Uses
	add := func(ref, job string) {
		if ref == "" {
			return
		}
		u := Uses{Ref: ref, Job: job, Target: ref}
		if i := strings.LastIndex(ref, "@"); i > 0 && !strings.HasPrefix(ref, "docker://") {
			u.Target, u.Ver = ref[:i], ref[i+1:]
		}
		out = append(out, u)
	}
	for _, j := range f.Jobs() {
		add(Str(j.Def, "uses"), j.ID)
		for _, s := range j.Steps() {
			add(Str(s, "uses"), j.ID)
		}
	}
	return out
}

// Permissions returns the workflow-level permissions value and whether it is set.
func (f File) Permissions() (any, bool) {
	v, ok := f.Doc["permissions"]
	return v, ok
}

// WriteAll reports whether the workflow or any job uses `permissions: write-all`.
func (f File) WriteAll() bool {
	if p, ok := f.Doc["permissions"].(string); ok && strings.TrimSpace(p) == "write-all" {
		return true
	}
	for _, j := range f.Jobs() {
		if p, ok := j.Def["permissions"].(string); ok && strings.TrimSpace(p) == "write-all" {
			return true
		}
	}
	return false
}

// JobsWithoutPermissions lists jobs that inherit the default token permissions.
func (f File) JobsWithoutPermissions() []string {
	if _, ok := f.Doc["permissions"]; ok {
		return nil
	}
	var out []string
	for _, j := range f.Jobs() {
		if _, ok := j.Def["permissions"]; !ok {
			out = append(out, j.ID)
		}
	}
	return out
}

// PrivilegedTriggers run with the base repository's secrets and a write
// token even when the event comes from a fork or an outside commenter.
var PrivilegedTriggers = []string{"pull_request_target", "workflow_run", "issue_comment"}

// prCode matches references to the pull request's own (untrusted) code.
var prCode = regexp.MustCompile(`(?i)github\.event\.pull_request\.head` +
	`|github\.event\.pull_request\.merge_commit_sha` +
	`|github\.head_ref` +
	`|github\.event\.workflow_run\.head` +
	`|refs/pull/` +
	`|\bpull/[^/\n]+/(head|merge)\b` +
	`|steps\.[\w-]+\.outputs\.[\w-]*head[\w-]*`)

var (
	gitFetch   = regexp.MustCompile(`(?i)\bgit\s+(fetch|checkout|switch|pull|clone)\b`)
	ghCheckout = regexp.MustCompile(`(?i)\bgh\s+pr\s+checkout\b`)
)

// PwnRequest reports jobs where a privileged trigger (pull_request_target,
// workflow_run, issue_comment) checks out pull-request code - with
// actions/checkout, `gh pr checkout` or git commands in a run step.
func (f File) PwnRequest() []string {
	if !f.HasTrigger(PrivilegedTriggers...) {
		return nil
	}
	var out []string
	for _, j := range f.Jobs() {
		for _, s := range j.Steps() {
			if ChecksOutPRCode(s) {
				out = append(out, j.ID)
				break
			}
		}
	}
	return out
}

// ChecksOutPRCode reports whether a step fetches the pull request's code.
func ChecksOutPRCode(step map[string]any) bool {
	if strings.HasPrefix(strings.ToLower(Str(step, "uses")), "actions/checkout") {
		with, _ := step["with"].(map[string]any)
		return prCode.MatchString(Str(with, "ref")) || prCode.MatchString(Str(with, "repository"))
	}
	run := Str(step, "run")
	return ghCheckout.MatchString(run) || (gitFetch.MatchString(run) && prCode.MatchString(run))
}

// LooksLikePwnRequest is a text-only heuristic for files that could not be
// parsed: a privileged trigger and a reference to pull-request code.
func LooksLikePwnRequest(raw string) bool {
	trig := false
	for _, t := range PrivilegedTriggers {
		trig = trig || strings.Contains(raw, t)
	}
	return trig && (prCode.MatchString(raw) || ghCheckout.MatchString(raw))
}

var staticKeyNames = map[string]bool{
	"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AZURE_CREDENTIALS": true,
	"GOOGLE_CREDENTIALS": true, "GCP_SA_KEY": true,
}

// StaticCloudKeys returns places where long-lived cloud keys come from secrets.
func (f File) StaticCloudKeys() []string {
	var out []string
	scanEnv := func(env any, where string) {
		m, _ := env.(map[string]any)
		for k, v := range m {
			if s, _ := v.(string); staticKeyNames[k] && strings.Contains(s, "secrets.") {
				out = append(out, where+" env "+k)
			}
		}
	}
	scanEnv(f.Doc["env"], "workflow")
	for _, j := range f.Jobs() {
		scanEnv(j.Def["env"], "job "+j.ID)
		for _, s := range j.Steps() {
			scanEnv(s["env"], "job "+j.ID)
			with, _ := s["with"].(map[string]any)
			for _, k := range []string{"aws-access-key-id", "aws-secret-access-key", "creds", "credentials_json"} {
				if v, _ := with[k].(string); strings.Contains(v, "secrets.") {
					out = append(out, "job "+j.ID+" input "+k)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// UsesOIDC reports whether any job requests an OIDC token for a cloud login.
func (f File) UsesOIDC() bool {
	has := func(p any) bool {
		m, _ := p.(map[string]any)
		return Str(m, "id-token") == "write"
	}
	if has(f.Doc["permissions"]) {
		return true
	}
	for _, j := range f.Jobs() {
		if has(j.Def["permissions"]) {
			return true
		}
	}
	return false
}
