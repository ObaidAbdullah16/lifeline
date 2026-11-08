package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ObaidAbdullah16/lifeline/internal/netcheck"
)

var accessChecks = []Check{
	{
		ID: "LL-ACC-001", Category: CatAccess, Title: "More than one person can administer the project", Weight: 8, Needs: NeedsRepo,
		Remediation: "Move the repository to a GitHub organisation with 2-5 owners. Store recovery codes for the registrar, DNS and cloud accounts somewhere a second maintainer can reach.",
		Run:         checkAdmins,
	},
	{
		ID: "LL-ACC-002", Category: CatAccess, Title: "Organisation requires two-factor authentication", Weight: 8, Needs: NeedsRepo,
		Remediation: "Organisation settings > Authentication security > Require two-factor authentication.",
		Run:         check2FA,
	},
	{
		ID: "LL-ACC-003", Category: CatAccess, Title: "Default branch is protected", Weight: 8, Needs: NeedsRepo,
		Remediation: "Add a ruleset for the default branch: require pull requests, block force pushes and deletions.",
		Run:         checkBranchProtection,
	},
	{
		ID: "LL-ACC-004", Category: CatAccess, Title: "Work is not concentrated in one maintainer (bus factor)", Weight: 6, Needs: NeedsRepo,
		Remediation: "Document how to release and deploy, give a second maintainer access, and pair on at least one release.",
		Run:         checkBusFactor,
	},
	{
		ID: "LL-ACC-005", Category: CatAccess, Title: "A security contact is published", Weight: 3, Needs: NeedsRepoOrPath,
		Remediation: "Add SECURITY.md (or /.well-known/security.txt on your domain) saying how to report vulnerabilities.",
		Run:         checkSecurityContact,
	},
}

func checkAdmins(e *Env, t Target) Result {
	r, err := e.Repo(t)
	if err != nil {
		return errResult(err)
	}
	if r.Owner.Type != "Organization" {
		return result(Fail, fmt.Sprintf("owned by the personal account %q: one person holds every key", r.Owner.Login))
	}
	admins, err := e.GH.OrgAdmins(e.Ctx, r.Owner.Login)
	if err != nil {
		return errResult(err)
	}
	// Only an organisation owner's token sees the 2FA setting, and only such a
	// token sees private memberships. Anyone else sees public members only, so
	// "one owner" may simply mean "one owner who made membership public".
	org, _ := e.Org(r.Owner.Login)
	ownerView := org != nil && org.TwoFactorRequired != nil
	note := ""
	if !ownerView {
		note = " (public memberships only)"
	}
	n := len(admins)
	msg := fmt.Sprintf("%d organisation owner(s) visible%s", n, note)
	switch {
	case n == 0:
		return result(Skip, "organisation owners are not publicly visible; run with an owner's token")
	case n < 2 && ownerView:
		return result(Fail, msg+": one person holds every key", admins...)
	case n < 2:
		return result(Warn, msg+": other owners may have private membership - confirm with an owner's token", admins...)
	case n > 5:
		return result(Warn, msg+": many owners widens the attack surface")
	}
	return result(Pass, msg)
}

func check2FA(e *Env, t Target) Result {
	r, err := e.Repo(t)
	if err != nil {
		return errResult(err)
	}
	if r.Owner.Type != "Organization" {
		return result(Skip, "personal account: 2FA enforcement is an organisation setting (turn on 2FA for your own account)")
	}
	org, err := e.Org(r.Owner.Login)
	if err != nil {
		return errResult(err)
	}
	if org.TwoFactorRequired == nil {
		return result(Skip, "only organisation owners can see this setting; run with an owner's token")
	}
	if *org.TwoFactorRequired {
		return result(Pass, "two-factor authentication is required for all members")
	}
	return result(Fail, "members can use the organisation without two-factor authentication")
}

func checkBranchProtection(e *Env, t Target) Result {
	r, err := e.Repo(t)
	if err != nil {
		return errResult(err)
	}
	protected, err := e.GH.BranchProtected(e.Ctx, t.Repo, r.DefaultBranch)
	if err != nil {
		return errResult(err)
	}
	rules, _ := e.GH.BranchRuleTypes(e.Ctx, t.Repo, r.DefaultBranch)
	sort.Strings(rules)
	var details []string
	if len(rules) > 0 {
		details = append(details, "ruleset rules: "+strings.Join(rules, ", "))
	}
	hasPR := false
	for _, x := range rules {
		if x == "pull_request" {
			hasPR = true
		}
	}
	switch {
	case hasPR:
		return result(Pass, fmt.Sprintf("%s requires pull requests", r.DefaultBranch), details...)
	case protected || len(rules) > 0:
		return result(Pass, fmt.Sprintf("%s is protected", r.DefaultBranch), details...)
	}
	return result(Fail, fmt.Sprintf("%s has no branch protection: anyone with write access can force-push or delete it", r.DefaultBranch))
}

// BusFactor returns the smallest number of authors responsible for at least 80% of commits.
func BusFactor(authors []string) (int, []string) {
	counts := map[string]int{}
	for _, a := range authors {
		counts[a]++
	}
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v == list[j].v {
			return list[i].k < list[j].k
		}
		return list[i].v > list[j].v
	})
	need := 0.8 * float64(len(authors))
	sum, n := 0, 0
	var top []string
	for _, x := range list {
		if float64(sum) >= need {
			break
		}
		sum += x.v
		n++
		top = append(top, fmt.Sprintf("%s: %d commits", x.k, x.v))
	}
	return n, top
}

func checkBusFactor(e *Env, t Target) Result {
	authors, err := e.GH.CommitAuthors(e.Ctx, t.Repo, e.Now.Add(-180*24*time.Hour), 300)
	if err != nil {
		return errResult(err)
	}
	if len(authors) == 0 {
		return result(Warn, "no human commits on the default branch in the last 180 days")
	}
	bf, top := BusFactor(authors)
	msg := fmt.Sprintf("bus factor %d: %d author(s) made 80%% of the last %d commits (180 days)", bf, bf, len(authors))
	switch {
	case bf >= 3:
		return result(Pass, msg, top...)
	case bf == 2:
		return result(Warn, msg, top...)
	}
	return result(Fail, msg, top...)
}

func checkSecurityContact(e *Env, t Target) Result {
	if e.Manifest != nil && e.Manifest.SecurityContact != "" {
		return result(Pass, "security_contact set in lifeline.yml: "+e.Manifest.SecurityContact)
	}
	for _, p := range []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"} {
		if _, ok := e.RepoFile(t, p); ok {
			return result(Pass, p+" found")
		}
	}
	if t.Domain != "" {
		if contacts, err := netcheck.SecurityTxt(e.Ctx, e.HTTP, "https://"+t.Domain); err == nil && len(contacts) > 0 {
			return result(Pass, "security.txt found", contacts...)
		}
	}
	return result(Fail, "no SECURITY.md or security.txt: researchers have no private way to report a vulnerability")
}
