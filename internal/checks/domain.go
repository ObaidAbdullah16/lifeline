package checks

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ObaidAbdullah16/lifeline/internal/netcheck"
)

var domainChecks = []Check{
	{
		ID: "LL-DOM-001", Category: CatDomain, Title: "Domain registration does not expire soon", Weight: 10, Needs: NeedsDomain,
		Remediation: "Turn on auto-renew at the registrar, renew for several years, and make sure at least two maintainers can log in to the registrar account.",
		Run:         checkDomainExpiry,
	},
	{
		ID: "LL-DOM-002", Category: CatDomain, Title: "TLS certificate is valid and not about to expire", Weight: 10, Needs: NeedsDomain,
		Remediation: "Automate renewal (Let's Encrypt/ACME, AWS ACM, Cloudflare) and alert when fewer than 14 days remain.",
		Run:         checkTLS,
	},
	{
		ID: "LL-DOM-003", Category: CatDomain, Title: "CAA record limits which CAs may issue certificates", Weight: 3, Needs: NeedsDomain,
		Remediation: "Add a CAA record, e.g. `example.org. CAA 0 issue \"letsencrypt.org\"`.",
		Run:         checkCAA,
	},
	{
		ID: "LL-DOM-004", Category: CatDomain, Title: "DNSSEC is enabled and validates", Weight: 3, Needs: NeedsDomain,
		Remediation: "Enable DNSSEC at your DNS provider and publish the DS record at the registrar.",
		Run:         checkDNSSEC,
	},
	{
		ID: "LL-DOM-005", Category: CatDomain, Title: "SPF and DMARC protect the domain from email spoofing", Weight: 5, Needs: NeedsDomain,
		Remediation: "Publish SPF (`v=spf1 ... -all`, or `v=spf1 -all` if the domain sends no mail) and DMARC with `p=quarantine` or `p=reject`.",
		Run:         checkEmailAuth,
	},
	{
		ID: "LL-DOM-006", Category: CatDomain, Title: "Outgoing email is signed with DKIM", Weight: 3, Needs: NeedsDomain,
		Remediation: "Turn on DKIM signing in every service that sends mail as the domain (Google Workspace, Microsoft 365, Zoho, SES, SendGrid...) and publish the key it gives you. List custom selectors under `dkim_selectors:` in lifeline.yml.",
		Run:         checkDKIM,
	},
	{
		ID: "LL-DOM-007", Category: CatDomain, Title: "SPF stays within the 10-DNS-lookup limit", Weight: 2, Needs: NeedsDomain,
		Remediation: "Remove senders you no longer use, replace `a`/`mx`/`ptr` with ip4/ip6 ranges, or flatten one include. Above 10 lookups receivers return permerror and SPF stops protecting the domain.",
		Run:         checkSPFLookups,
	},
}

// CommonDKIMSelectors are tried when lifeline.yml lists none: the defaults of the
// providers small teams use most (Google, Microsoft 365, Zoho, Mailchimp, SendGrid,
// Fastmail, Proton, ImprovMX, Amazon SES with custom MAIL FROM and generic names).
var CommonDKIMSelectors = []string{
	"google", "selector1", "selector2", "zoho", "zmail", "k1", "k2", "s1", "s2", "fm1", "fm2", "fm3",
	"protonmail", "protonmail2", "protonmail3", "dkimprovmx1", "dkimprovmx2", "default", "dkim", "mail", "smtp", "mandrill", "mxvault",
	"everlytickey1", "cm",
}

func checkDKIM(e *Env, t Target) Result {
	apex := e.Apex(t.Domain)
	if sendsNoMail(e, apex) {
		return result(Skip, fmt.Sprintf("%s publishes `v=spf1 -all` and has no MX record: it sends no email, so there is nothing to sign", apex))
	}
	selectors := append([]string{}, CommonDKIMSelectors...)
	if e.Manifest != nil && len(e.Manifest.DKIMSelectors) > 0 {
		selectors = append(append([]string{}, e.Manifest.DKIMSelectors...), selectors...)
	}
	var found, revoked []string
	seen := map[string]bool{}
	for _, sel := range selectors {
		if seen[sel] {
			continue
		}
		seen[sel] = true
		txt, err := e.DNS.TXT(e.Ctx, sel+"._domainkey."+apex)
		if err != nil {
			return errResult(err)
		}
		for _, r := range txt {
			l := strings.ToLower(strings.ReplaceAll(r, " ", ""))
			if !strings.Contains(l, "p=") || !(strings.Contains(l, "v=dkim1") || strings.Contains(l, "k=rsa") || strings.Contains(l, "k=ed25519") || strings.HasPrefix(l, "p=")) {
				continue
			}
			if strings.Contains(l, "p=;") || strings.HasSuffix(l, "p=") {
				revoked = append(revoked, sel)
			} else {
				found = append(found, sel)
			}
			break
		}
	}
	switch {
	case len(found) > 0:
		return result(Pass, fmt.Sprintf("DKIM key published for selector(s): %s", strings.Join(found, ", ")))
	case len(revoked) > 0:
		return result(Warn, fmt.Sprintf("only revoked DKIM keys (empty p=) found for: %s", strings.Join(revoked, ", ")))
	}
	return result(Warn, fmt.Sprintf("no DKIM key found on %d common selectors; if your provider uses another one, add it to `dkim_selectors:` in lifeline.yml", len(seen)))
}

// sendsNoMail reports a domain that declares it sends nothing (SPF "-all" only) and receives nothing (no MX).
func sendsNoMail(e *Env, apex string) bool {
	txt, err := e.DNS.TXT(e.Ctx, apex)
	if err != nil {
		return false
	}
	nullSPF := false
	for _, r := range txt {
		if strings.EqualFold(strings.Join(strings.Fields(r), " "), "v=spf1 -all") {
			nullSPF = true
		}
	}
	if !nullSPF {
		return false
	}
	mx, err := e.DNS.Query(e.Ctx, apex, "MX")
	return err == nil && len(mx.Records(netcheck.TypeMX)) == 0
}

// spfLookupLimit is RFC 7208's cap on DNS-querying mechanisms per SPF evaluation.
const spfLookupLimit = 10

func checkSPFLookups(e *Env, t Target) Result {
	apex := e.Apex(t.Domain)
	spf, err := spfRecord(e, apex)
	if err != nil {
		return errResult(err)
	}
	if spf == "" {
		return result(Skip, "no SPF record (see LL-DOM-005)")
	}
	n, chain, err := countSPFLookups(e, spf, 0, map[string]bool{apex: true})
	if err != nil {
		return result(Warn, "could not resolve every include: "+shortErr(err), "SPF: "+spf)
	}
	msg := fmt.Sprintf("SPF needs %d of the 10 allowed DNS lookups", n)
	details := append([]string{"SPF: " + spf}, chain...)
	switch {
	case n > spfLookupLimit:
		return result(Fail, msg+": receivers return permerror, so SPF does not protect the domain", details...)
	case n >= 9:
		return result(Warn, msg+": one more sending service will break it", details...)
	}
	return result(Pass, msg, details...)
}

func spfRecord(e *Env, name string) (string, error) {
	txt, err := e.DNS.TXT(e.Ctx, name)
	if err != nil {
		return "", err
	}
	for _, r := range txt {
		if l := strings.ToLower(r); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			return r, nil
		}
	}
	return "", nil
}

// countSPFLookups counts include, a, mx, ptr, exists and redirect, following includes and redirects.
func countSPFLookups(e *Env, spf string, depth int, visited map[string]bool) (int, []string, error) {
	if depth > 10 {
		return 0, nil, errors.New("include chain deeper than 10")
	}
	n := 0
	var chain []string
	for _, term := range strings.Fields(strings.ToLower(spf))[1:] {
		mech := strings.TrimLeft(term, "+-~?")
		var target string
		switch {
		case strings.HasPrefix(mech, "include:"):
			target = strings.TrimPrefix(mech, "include:")
		case strings.HasPrefix(mech, "redirect="):
			target = strings.TrimPrefix(mech, "redirect=")
		case mech == "a" || strings.HasPrefix(mech, "a:") || strings.HasPrefix(mech, "a/"),
			mech == "mx" || strings.HasPrefix(mech, "mx:") || strings.HasPrefix(mech, "mx/"),
			mech == "ptr" || strings.HasPrefix(mech, "ptr:"),
			strings.HasPrefix(mech, "exists:"):
			n++
			continue
		default:
			continue
		}
		n++
		if visited[target] { // a loop: receivers stop with permerror; count the term and stop
			chain = append(chain, target+": include loop")
			continue
		}
		inner, err := spfRecord(e, target)
		if err != nil {
			return n, chain, err
		}
		if inner == "" {
			chain = append(chain, target+": no SPF record (counts as an error for receivers)")
			continue
		}
		visited[target] = true // the current include path; the same domain included twice is counted twice, as receivers do
		m, sub, err := countSPFLookups(e, inner, depth+1, visited)
		delete(visited, target)
		if err != nil {
			return n, chain, err
		}
		chain = append(chain, fmt.Sprintf("%s: %d lookup(s)", target, m+1))
		chain = append(chain, sub...)
		n += m
	}
	return n, chain, nil
}

func checkDomainExpiry(e *Env, t Target) Result {
	reg, err := e.Registration(t.Domain)
	if errors.Is(err, netcheck.ErrNoRDAP) {
		return result(Skip, "no RDAP service for this TLD; check the expiry date at your registrar and enable auto-renew")
	}
	if errors.Is(err, netcheck.ErrNoExpiration) {
		return result(Skip, fmt.Sprintf("the registry's RDAP record for %s has no expiry date; check it at your registrar and enable auto-renew", reg.Domain))
	}
	if err != nil {
		return errResult(err)
	}
	left := days(reg.Expiration.Sub(e.Now))
	who := ""
	if reg.Registrar != "" {
		who = " (registrar: " + reg.Registrar + ")"
	}
	msg := fmt.Sprintf("%s expires on %s, in %d days%s", reg.Domain, reg.Expiration.Format("2006-01-02"), left, who)
	switch {
	case left < 30:
		return result(Fail, msg)
	case left < 90:
		return result(Warn, msg)
	}
	return result(Pass, msg)
}

func checkTLS(e *Env, t Target) Result {
	cert, err := e.TLS.Certificate(e.Ctx, t.Domain)
	if err != nil {
		return result(Fail, "could not complete a TLS handshake on port 443: "+shortErr(err))
	}
	left := days(cert.NotAfter.Sub(e.Now))
	detail := fmt.Sprintf("issuer %s, expires %s", cert.Issuer, cert.NotAfter.Format("2006-01-02"))
	if !cert.VerifyOK {
		return result(Fail, "certificate does not verify: "+cert.VerifyErr, detail)
	}
	msg := fmt.Sprintf("certificate valid for %d more days", left)
	switch {
	case left < 7:
		return result(Fail, msg, detail)
	case left < 14:
		return result(Warn, msg, detail)
	}
	return result(Pass, msg, detail)
}

func checkCAA(e *Env, t Target) Result {
	for _, name := range netcheck.Parents(t.Domain) {
		a, err := e.DNS.Query(e.Ctx, name, "CAA")
		if err != nil {
			return errResult(err)
		}
		if recs := a.Records(netcheck.TypeCAA); len(recs) > 0 {
			return result(Pass, fmt.Sprintf("CAA set on %s", name), recs...)
		}
	}
	return result(Warn, "no CAA record: any certificate authority may issue certificates for this domain")
}

func checkDNSSEC(e *Env, t Target) Result {
	apex := e.Apex(t.Domain)
	ds, err := e.DNS.Query(e.Ctx, apex, "DS")
	if err != nil {
		return errResult(err)
	}
	if len(ds.Records(netcheck.TypeDS)) == 0 {
		return result(Warn, fmt.Sprintf("%s is not DNSSEC-signed", apex))
	}
	// Ask about the signed zone itself (its SOA record), not the scanned host:
	// www may be a CNAME to an unsigned CDN, which is "insecure", not broken.
	soa, err := e.DNS.Query(e.Ctx, apex, "SOA")
	if err != nil {
		return errResult(err)
	}
	switch {
	case soa.Status == netcheck.RcodeServFail:
		return result(Fail, fmt.Sprintf("%s has a DS record but validating resolvers answer SERVFAIL - a broken DNSSEC chain takes the domain offline for them", apex))
	case soa.AD:
		return result(Pass, fmt.Sprintf("%s is signed (DS at parent) and answers validate", apex))
	}
	return result(Warn, fmt.Sprintf("%s has a DS record, but the resolver did not mark its answers as validated", apex))
}

func checkEmailAuth(e *Env, t Target) Result {
	apex := e.Apex(t.Domain)
	txt, err := e.DNS.TXT(e.Ctx, apex)
	if err != nil {
		return errResult(err)
	}
	spf, spfCount := "", 0
	for _, r := range txt {
		if l := strings.ToLower(r); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			spf = r
			spfCount++
		}
	}
	dtxt, err := e.DNS.TXT(e.Ctx, "_dmarc."+apex)
	if err != nil {
		return errResult(err)
	}
	dmarc, policy, dmarcCount := "", "", 0
	for _, r := range dtxt {
		if strings.HasPrefix(strings.ToLower(r), "v=dmarc1") {
			dmarc = r
			dmarcCount++
			for _, part := range strings.Split(r, ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 && strings.EqualFold(kv[0], "p") {
					policy = strings.ToLower(strings.TrimSpace(kv[1]))
				}
			}
		}
	}
	var details []string
	if spf != "" {
		details = append(details, "SPF: "+spf)
	}
	if dmarc != "" {
		details = append(details, "DMARC: "+dmarc)
	}
	switch {
	case spf == "" && dmarc == "":
		return result(Fail, fmt.Sprintf("%s has neither SPF nor DMARC: anyone can send email as @%s", apex, apex))
	case spfCount > 1:
		return result(Warn, fmt.Sprintf("%s publishes %d SPF records; receivers treat that as an error and ignore SPF", apex, spfCount), details...)
	case spfAllowsAll(spf):
		return result(Warn, "SPF ends in +all (or a bare all): every server on the internet is allowed to send as this domain", details...)
	case dmarcCount > 1:
		return result(Warn, fmt.Sprintf("_dmarc.%s has %d DMARC records; receivers ignore DMARC when there is more than one", apex, dmarcCount), details...)
	case dmarc != "" && policy == "":
		return result(Warn, "the DMARC record has no p= tag, so it sets no policy", details...)
	case dmarc == "":
		return result(Warn, "SPF present but no DMARC record", details...)
	case spf == "":
		return result(Warn, "DMARC present but no SPF record", details...)
	case policy == "quarantine" || policy == "reject":
		return result(Pass, fmt.Sprintf("SPF and DMARC (p=%s) are published", policy), details...)
	}
	return result(Warn, fmt.Sprintf("DMARC policy is p=%s (monitoring only)", policy), details...)
}

// spfAllowsAll reports an SPF record whose final mechanism lets any host pass.
func spfAllowsAll(spf string) bool {
	f := strings.Fields(strings.ToLower(spf))
	if len(f) == 0 {
		return false
	}
	last := f[len(f)-1]
	return last == "+all" || last == "all"
}
