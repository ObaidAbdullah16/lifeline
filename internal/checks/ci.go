package checks

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ObaidAbdullah16/lifeline/internal/workflows"
	"github.com/ObaidAbdullah16/lifeline/internal/yamlite"
)

var ciChecks = []Check{
	{
		ID: "LL-CI-001", Category: CatCI, Title: "Actions are pinned to commit SHAs", Weight: 8, Needs: NeedsRepoOrPath,
		Remediation: "Pin each `uses:` to a full commit SHA with the version as a comment (tools like pinact or gha-hardening-kit's pin_actions.py do it), and let Dependabot update the pins.",
		Run:         checkPinned,
	},
	{
		ID: "LL-CI-002", Category: CatCI, Title: "Workflow token permissions are restricted", Weight: 6, Needs: NeedsRepoOrPath,
		Remediation: "Add `permissions: {}` or `contents: read` at the top of each workflow and grant more per job. Never use write-all.",
		Run:         checkPermissions,
	},
	{
		ID: "LL-CI-003", Category: CatCI, Title: "No privileged workflow runs untrusted pull-request code", Weight: 10, Needs: NeedsRepoOrPath,
		Remediation: "Do not check out the PR head in pull_request_target/workflow_run jobs. Build PR code under `pull_request`, which has no secrets.",
		Run:         checkPwnRequest,
	},
	{
		ID: "LL-CI-004", Category: CatCI, Title: "Cloud access uses short-lived OIDC credentials", Weight: 8, Needs: NeedsRepoOrPath,
		Remediation: "Replace stored cloud keys with OIDC (`permissions: id-token: write` + role-to-assume) and delete the old keys.",
		Run:         checkCloudKeys,
	},
	{
		ID: "LL-CI-005", Category: CatCI, Title: "Dependencies and actions are updated automatically", Weight: 4, Needs: NeedsRepoOrPath,
		Remediation: "Add .github/dependabot.yml with the github-actions ecosystem (and a cooldown), or configure Renovate.",
		Run:         checkUpdates,
	},
}

func loadWF(e *Env, t Target) ([]workflows.File, *Result) {
	wfs, err := e.Workflows(t)
	if err != nil {
		r := errResult(err)
		return nil, &r
	}
	if len(wfs) == 0 {
		r := result(Skip, "no GitHub Actions workflows found")
		return nil, &r
	}
	return wfs, nil
}

// withUnparsed notes workflow files yamlite could not parse. Their findings
// are unknown, so a clean result becomes a warning instead of a pass.
func withUnparsed(r Result, wfs []workflows.File, extra func(workflows.File) string) Result {
	var bad []string
	for _, f := range wfs {
		if f.Err == nil {
			continue
		}
		d := fmt.Sprintf("not analysed (could not parse %s: %s)", f.Path, shortErr(f.Err))
		if extra != nil {
			d += extra(f)
		}
		bad = append(bad, d)
		if r.Location == "" {
			r.Location = f.Path
		}
	}
	if len(bad) == 0 {
		return r
	}
	r.Details = append(r.Details, bad...)
	if r.Status == Pass {
		r.Status, r.Score = Warn, 0
		r.Summary += fmt.Sprintf("; %d workflow file(s) could not be parsed and were not checked", len(bad))
	}
	return r
}

func checkPinned(e *Env, t Target) Result {
	wfs, early := loadWF(e, t)
	if early != nil {
		return *early
	}
	total, pinned := 0, 0
	var unpinned []string
	seen := map[string]int{}
	first := ""
	for _, f := range wfs {
		for _, u := range f.AllUses() {
			if u.Local() {
				continue
			}
			total++
			if u.Pinned() {
				pinned++
				continue
			}
			if first == "" {
				first = f.Path
			}
			key := fmt.Sprintf("%s: %s", f.Path, u.Ref)
			if seen[key] == 0 {
				unpinned = append(unpinned, key)
			}
			seen[key]++
		}
	}
	for i, k := range unpinned {
		if n := seen[k]; n > 1 {
			unpinned[i] = fmt.Sprintf("%s (x%d)", k, n)
		}
	}
	if total == 0 {
		return withUnparsed(result(Pass, "workflows use no external actions"), wfs, nil)
	}
	share := float64(pinned) / float64(total)
	sort.Strings(unpinned)
	if len(unpinned) > 10 {
		unpinned = append(unpinned[:10], fmt.Sprintf("... and %d more", len(unpinned)-10))
	}
	res := result(Pass, fmt.Sprintf("%d of %d action references pinned (%.0f%%)", pinned, total, share*100), unpinned...)
	res.Score = int(math.Floor(share * 10)) // 19 of 20 pinned = 9 points, never a full 10
	res.Location = first
	switch {
	case pinned == total:
		res.Score = 10
	case share >= 0.5:
		res.Status = Warn
	default:
		res.Status = Fail
	}
	return withUnparsed(res, wfs, nil)
}

func checkPermissions(e *Env, t Target) Result {
	wfs, early := loadWF(e, t)
	if early != nil {
		return *early
	}
	var writeAll, open []string
	for _, f := range wfs {
		if f.Err != nil {
			continue
		}
		if f.WriteAll() {
			writeAll = append(writeAll, f.Path)
		}
		if jobs := f.JobsWithoutPermissions(); len(jobs) > 0 {
			open = append(open, fmt.Sprintf("%s (jobs: %s)", f.Path, strings.Join(jobs, ", ")))
		}
	}
	switch {
	case len(writeAll) > 0:
		r := result(Fail, fmt.Sprintf("%d workflow(s) use permissions: write-all", len(writeAll)), writeAll...)
		r.Location = writeAll[0]
		return withUnparsed(r, wfs, nil)
	case len(open) > 0:
		r := result(Warn, fmt.Sprintf("%d of %d workflow(s) rely on the repository's default token permissions", len(open), len(wfs)), open...)
		r.Location = strings.SplitN(open[0], " ", 2)[0]
		return withUnparsed(r, wfs, nil)
	}
	return withUnparsed(result(Pass, fmt.Sprintf("all %d workflow(s) declare token permissions", len(wfs))), wfs, nil)
}

func checkPwnRequest(e *Env, t Target) Result {
	wfs, early := loadWF(e, t)
	if early != nil {
		return *early
	}
	var bad []string
	for _, f := range wfs {
		for _, job := range f.PwnRequest() {
			bad = append(bad, fmt.Sprintf("%s job %s", f.Path, job))
		}
	}
	suspect := func(f workflows.File) string {
		if workflows.LooksLikePwnRequest(f.Raw) {
			return " - it mentions a privileged trigger and pull-request code: review it by hand"
		}
		return ""
	}
	if len(bad) > 0 {
		r := result(Fail, "pull-request code runs with secrets and a write token (\"pwn request\")", bad...)
		r.Location = strings.SplitN(bad[0], " ", 2)[0]
		return withUnparsed(r, wfs, suspect)
	}
	return withUnparsed(result(Pass, "no pull_request_target, workflow_run or issue_comment job checks out pull-request code"), wfs, suspect)
}

func checkCloudKeys(e *Env, t Target) Result {
	wfs, early := loadWF(e, t)
	if early != nil {
		return *early
	}
	var keys []string
	oidc := false
	loc := ""
	for _, f := range wfs {
		for _, k := range f.StaticCloudKeys() {
			keys = append(keys, f.Path+": "+k)
			if loc == "" {
				loc = f.Path
			}
		}
		oidc = oidc || f.UsesOIDC()
	}
	if len(keys) > 0 {
		r := result(Fail, "long-lived cloud credentials are stored as secrets", keys...)
		r.Location = loc
		return withUnparsed(r, wfs, nil)
	}
	if oidc {
		return withUnparsed(result(Pass, "no stored cloud keys found; workflows request short-lived OIDC tokens (id-token: write)"), wfs, nil)
	}
	return withUnparsed(result(Pass, "no stored cloud keys found in workflows"), wfs, nil)
}

func checkUpdates(e *Env, t Target) Result {
	for _, p := range []string{".github/dependabot.yml", ".github/dependabot.yaml"} {
		text, ok := e.RepoFile(t, p)
		if !ok {
			continue
		}
		doc, err := yamlite.ParseMap(text)
		if err != nil {
			return result(Warn, p+" exists but could not be parsed: "+err.Error())
		}
		var ecos []string
		actions := false
		list, _ := doc["updates"].([]any)
		for _, u := range list {
			m, _ := u.(map[string]any)
			eco := workflows.Str(m, "package-ecosystem")
			ecos = append(ecos, eco)
			if eco == "github-actions" {
				actions = true
			}
		}
		if actions {
			return result(Pass, "Dependabot updates: "+strings.Join(ecos, ", "))
		}
		r := result(Warn, "Dependabot is configured but not for github-actions", "ecosystems: "+strings.Join(ecos, ", "))
		r.Location = p
		return r
	}
	for _, p := range []string{"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json", ".github/renovate.json5"} {
		if _, ok := e.RepoFile(t, p); ok {
			return result(Pass, "Renovate configured ("+p+")")
		}
	}
	return result(Fail, "nothing updates dependencies or pinned actions automatically")
}
