package checks

import (
	"fmt"
	"math"
	"time"
)

var backupChecks = []Check{
	{
		ID: "LL-BAK-001", Category: CatBackup, Title: "Backups are declared for stateful data", Weight: 8, Needs: NeedsManifest,
		Remediation: "List every backup in lifeline.yml (database dumps, object storage copies, repository mirrors). If the project truly has no state, add LL-BAK-* to `ignore:` with a reason.",
		Run:         checkBackupsDeclared,
	},
	{
		ID: "LL-BAK-002", Category: CatBackup, Title: "Restores have been tested recently", Weight: 8, Needs: NeedsManifest,
		Remediation: "Restore each backup into a sandbox at least every 90 days, check the data, record the date in lifeline.yml (restore-drill-kit automates this).",
		Run:         checkRestoreTested,
	},
	{
		ID: "LL-BAK-003", Category: CatBackup, Title: "Backups are isolated from production credentials", Weight: 8, Needs: NeedsManifest,
		Remediation: "Keep backups in a separate account/project or with object lock, so whoever (or whatever AI agent) can delete production cannot delete the backups.",
		Run:         checkBackupIsolation,
	},
}

var costChecks = []Check{
	{
		ID: "LL-COST-001", Category: CatCost, Title: "Infrastructure money lasts at least six months", Weight: 8, Needs: NeedsManifest,
		Remediation: "Apply for credits or sponsorship early, cut idle resources, and plan what to switch off if funding stops.",
		Run:         checkRunway,
	},
	{
		ID: "LL-COST-002", Category: CatCost, Title: "Billing alerts are configured", Weight: 4, Needs: NeedsManifest,
		Remediation: "Create a monthly budget with alerts at 50/80/100% (AWS Budgets, GCP budgets, Azure cost alerts) and set budget_alerts: true.",
		Run:         checkBudgetAlerts,
	},
}

// manifestLoc is the repository-relative path of lifeline.yml, used as the
// SARIF location (an absolute path would not map to a file in code scanning).
func manifestLoc(e *Env) string {
	if e.Manifest != nil && e.Manifest.RelPath != "" {
		return e.Manifest.RelPath
	}
	return "lifeline.yml"
}

func checkBackupsDeclared(e *Env, t Target) Result {
	m := e.Manifest
	r := Result{Location: manifestLoc(e)}
	switch {
	case !m.BackupsSet:
		r.Status, r.Summary = Fail, "lifeline.yml has no `backups:` section"
	case len(m.Backups) == 0:
		r.Status, r.Summary = Fail, "lifeline.yml declares no backups"
	default:
		r.Status, r.Summary = Pass, fmt.Sprintf("%d backup(s) declared", len(m.Backups))
		for _, b := range m.Backups {
			r.Details = append(r.Details, fmt.Sprintf("%s: %s -> %s", b.Name, b.What, b.Location))
		}
	}
	return r
}

func checkRestoreTested(e *Env, t Target) Result {
	m := e.Manifest
	if len(m.Backups) == 0 {
		return result(Skip, "no backups declared")
	}
	worst := Pass
	var details []string
	for _, b := range m.Backups {
		if b.LastRestoreTest.IsZero() {
			worst = Fail
			details = append(details, b.Name+": never restored")
			continue
		}
		age := days(e.Now.Sub(b.LastRestoreTest))
		if age < 0 {
			if rank(Warn) > rank(worst) {
				worst = Warn
			}
			details = append(details, fmt.Sprintf("%s: last_restore_test %s is in the future (typo?)", b.Name, b.LastRestoreTest.Format("2006-01-02")))
			continue
		}
		st := Pass
		switch {
		case age > 180:
			st = Fail
		case age > 90:
			st = Warn
		}
		if rank(st) > rank(worst) {
			worst = st
		}
		details = append(details, fmt.Sprintf("%s: last restore test %s (%d days ago)", b.Name, b.LastRestoreTest.Format("2006-01-02"), age))
	}
	r := result(worst, map[Status]string{
		Pass: "every backup was restored in the last 90 days",
		Warn: "a backup has not been restored for over 90 days, or its date is wrong",
		Fail: "a backup was never restored or not for over 180 days",
	}[worst], details...)
	r.Location = manifestLoc(e)
	return r
}

func checkBackupIsolation(e *Env, t Target) Result {
	m := e.Manifest
	if len(m.Backups) == 0 {
		return result(Skip, "no backups declared")
	}
	var shared []string
	for _, b := range m.Backups {
		if !b.Isolated {
			reason := "isolated: false"
			if !b.IsolatedSet {
				reason = "isolation not stated"
			}
			shared = append(shared, fmt.Sprintf("%s (%s)", b.Name, reason))
		}
	}
	if len(shared) > 0 {
		r := result(Warn, "some backups may be deletable with production credentials", shared...)
		r.Location = manifestLoc(e)
		return r
	}
	return result(Pass, "every backup is isolated from production credentials")
}

func rank(s Status) int {
	switch s {
	case Fail:
		return 2
	case Warn:
		return 1
	}
	return 0
}

// RunwayDays computes how many days credits and cash cover the monthly spend.
// Credits that would expire before they can be used are not counted.
func RunwayDays(monthly, credits, cash float64, expires, now time.Time) float64 {
	if monthly <= 0 {
		return math.Inf(1)
	}
	daily := monthly / 30.44
	if !expires.IsZero() {
		usable := math.Max(0, expires.Sub(now).Hours()/24) * daily
		credits = math.Min(credits, usable)
	}
	return (credits + cash) / daily
}

func checkRunway(e *Env, t Target) Result {
	c := e.Manifest.Cost
	if !c.Set {
		r := result(Fail, "lifeline.yml has no `cost:` section")
		r.Location = manifestLoc(e)
		return r
	}
	if c.MonthlySpendUSD <= 0 {
		return result(Pass, "no recurring infrastructure spend declared")
	}
	d := RunwayDays(c.MonthlySpendUSD, c.CreditsUSD, c.CashUSD, c.CreditsExpire, e.Now)
	msg := fmt.Sprintf("$%.0f/month covered for about %.0f days", c.MonthlySpendUSD, d)
	var details []string
	if !c.CreditsExpire.IsZero() {
		verb := "expire"
		if c.CreditsExpire.Before(e.Now) {
			verb = "expired" // and count for nothing in the runway
		}
		details = append(details, fmt.Sprintf("credits ($%.0f) %s %s", c.CreditsUSD, verb, c.CreditsExpire.Format("2006-01-02")))
	}
	st := Pass
	switch {
	case d < 60:
		st = Fail
	case d < 180:
		st = Warn
	}
	if !c.CreditsExpire.IsZero() && !c.CreditsExpire.Before(e.Now) && c.CreditsExpire.Sub(e.Now) < 60*24*time.Hour && st == Pass {
		st = Warn
		details = append(details, "credits expire within 60 days")
	}
	r := result(st, msg, details...)
	r.Location = manifestLoc(e)
	return r
}

func checkBudgetAlerts(e *Env, t Target) Result {
	c := e.Manifest.Cost
	r := Result{Location: manifestLoc(e)}
	switch {
	case !c.Set || !c.BudgetAlertsSet:
		r.Status, r.Summary = Fail, "budget_alerts not declared in lifeline.yml"
	case c.BudgetAlerts:
		r.Status, r.Summary = Pass, "billing alerts are configured"
	default:
		r.Status, r.Summary = Fail, "no billing alerts: a runaway bill is noticed only on the invoice"
	}
	return r
}
