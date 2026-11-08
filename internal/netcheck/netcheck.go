// Package netcheck performs the outside-in network lookups behind the domain
// checks: DNS over HTTPS (JSON API), RDAP registration data, TLS certificates
// and security.txt. Standard library only.
package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNoRDAP means no RDAP service answered for the domain or any parent.
var ErrNoRDAP = errors.New("no RDAP data available for this domain")

// ErrNoExpiration means the registry answered but published no expiry date.
// Lookup still returns the Registration (its Domain is the registrable name).
var ErrNoExpiration = errors.New("RDAP record has no expiration date")

// Resolver answers DNS questions over HTTPS using the JSON API offered by
// Cloudflare (cloudflare-dns.com) and Google (dns.google).
type Resolver struct {
	Endpoints []string // tried in order
	HTTP      *http.Client
}

// NewResolver returns a resolver with Cloudflare first and Google as fallback.
func NewResolver() *Resolver {
	return &Resolver{
		Endpoints: []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"},
		HTTP:      &http.Client{Timeout: 10 * time.Second},
	}
}

// Answer is a DNS response.
type Answer struct {
	Status int  `json:"Status"` // 0 NOERROR, 3 NXDOMAIN
	AD     bool `json:"AD"`     // response was DNSSEC-validated by the resolver
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// RcodeServFail is the DNS status a validating resolver returns when DNSSEC
// validation fails (the answer is "bogus").
const RcodeServFail = 2

// DNS record type numbers used by the checks.
const (
	TypeA     = 1
	TypeMX    = 15
	TypeTXT   = 16
	TypeDS    = 43
	TypeCAA   = 257
	TypeCNAME = 5
)

// Records returns the data of answers with the given type.
func (a *Answer) Records(t int) []string {
	var out []string
	for _, r := range a.Answer {
		if r.Type == t {
			out = append(out, r.Data)
		}
	}
	return out
}

// Query asks for name/type ("A", "TXT", "CAA", "DS", "SOA").
func (r *Resolver) Query(ctx context.Context, name, typ string) (*Answer, error) {
	var lastErr error
	for _, ep := range r.Endpoints {
		u := fmt.Sprintf("%s?name=%s&type=%s&do=true", ep, url.QueryEscape(name), url.QueryEscape(typ))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := r.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", ep, resp.StatusCode)
			continue
		}
		var a Answer
		if err := json.Unmarshal(body, &a); err != nil {
			lastErr = err
			continue
		}
		return &a, nil
	}
	return nil, fmt.Errorf("DNS query %s %s failed: %w", name, typ, lastErr)
}

// TXT returns TXT strings with the quoting and chunking removed.
func (r *Resolver) TXT(ctx context.Context, name string) ([]string, error) {
	a, err := r.Query(ctx, name, "TXT")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range a.Records(TypeTXT) {
		out = append(out, JoinTXT(d))
	}
	return out, nil
}

// JoinTXT turns `"v=spf1 include:a" " -all"` into `v=spf1 include:a -all`.
func JoinTXT(d string) string {
	d = strings.TrimSpace(d)
	if !strings.HasPrefix(d, "\"") {
		return d
	}
	var b strings.Builder
	in := false
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c == '\\' && in && i+1 < len(d):
			i++
			b.WriteByte(d[i])
		case c == '"':
			in = !in
		case in:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// twoLabelSuffixes are common public suffixes with two labels. Lifeline has
// no third-party modules, so it carries this short list instead of the full
// Public Suffix List; RDAP answers take precedence whenever they exist.
var twoLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.in": true, "net.in": true, "org.in": true, "firm.in": true, "gen.in": true, "ind.in": true, "ac.in": true, "edu.in": true, "gov.in": true, "res.in": true,
	"co.nz": true, "org.nz": true, "net.nz": true, "ac.nz": true, "govt.nz": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	"co.za": true, "org.za": true, "com.br": true, "org.br": true, "net.br": true,
	"com.cn": true, "org.cn": true, "net.cn": true, "com.mx": true, "org.mx": true,
	"com.tr": true, "com.sg": true, "org.sg": true, "com.my": true, "co.kr": true, "or.kr": true,
	"co.id": true, "or.id": true, "com.pk": true, "org.pk": true, "com.ng": true, "org.ng": true,
	"co.il": true, "org.il": true, "com.ar": true, "com.co": true, "com.ua": true, "com.hk": true, "com.tw": true,
}

// GuessApex returns the registrable domain of name without network access:
// the last two labels, or three when the last two are a known two-label
// suffix (www.example.co.uk -> example.co.uk).
func GuessApex(name string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	n := 2
	if len(labels) >= 3 && twoLabelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) <= n {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// Parents returns name and its parent domains, stopping before the TLD:
// a.b.example.org -> [a.b.example.org b.example.org example.org].
func Parents(name string) []string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	var out []string
	for i := 0; i+2 <= len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// ----------------------------------------------------------------------- RDAP

// RDAP looks up domain registration data via the rdap.org bootstrap redirector.
type RDAP struct {
	BaseURL string // default https://rdap.org
	HTTP    *http.Client
}

// NewRDAP returns an RDAP client.
func NewRDAP() *RDAP {
	return &RDAP{BaseURL: "https://rdap.org", HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Registration is what the domain checks need from RDAP.
type Registration struct {
	Domain     string
	Expiration time.Time
	Registrar  string
}

// Lookup tries the domain and then its parents (so docs.example.org finds example.org).
// With ErrNoExpiration the Registration is returned too.
func (r *RDAP) Lookup(ctx context.Context, domain string) (*Registration, error) {
	for _, d := range Parents(domain) {
		reg, err := r.lookupOne(ctx, d)
		switch {
		case err == nil, errors.Is(err, ErrNoExpiration):
			return reg, err
		case !errors.Is(err, ErrNoRDAP):
			return nil, err
		}
	}
	return nil, ErrNoRDAP
}

func (r *RDAP) lookupOne(ctx context.Context, d string) (*Registration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(r.BaseURL, "/")+"/domain/"+url.PathEscape(d), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return nil, ErrNoRDAP
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP %s: HTTP %d", d, resp.StatusCode)
	}
	var doc struct {
		LDHName string `json:"ldhName"`
		Events  []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	reg := &Registration{Domain: strings.ToLower(doc.LDHName)}
	if reg.Domain == "" {
		reg.Domain = d
	}
	for _, e := range doc.Events {
		if e.Action == "expiration" {
			if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
				reg.Expiration = t
			}
		}
	}
	for _, ent := range doc.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				reg.Registrar = vcardFN(ent.VCardArray)
			}
		}
	}
	if reg.Expiration.IsZero() {
		return reg, fmt.Errorf("%s: %w", d, ErrNoExpiration)
	}
	return reg, nil
}

// vcardFN extracts the "fn" (formatted name) from a jCard array.
func vcardFN(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		arr, _ := p.([]any)
		if len(arr) >= 4 && arr[0] == "fn" {
			s, _ := arr[3].(string)
			return s
		}
	}
	return ""
}

// ------------------------------------------------------------------------ TLS

// CertInfo describes the certificate served on port 443.
type CertInfo struct {
	NotAfter  time.Time
	Issuer    string
	DNSNames  []string
	VerifyOK  bool
	VerifyErr string
}

// TLSDialer fetches certificates. Addr overrides host:port (used in tests).
type TLSDialer struct {
	Timeout time.Duration
	Roots   *x509.CertPool // nil = system roots
	Addr    func(host string) string
}

// Certificate connects to host:443 and returns the leaf certificate.
// It always returns the certificate when the handshake completes, and records
// whether normal verification would have succeeded.
func (d *TLSDialer) Certificate(ctx context.Context, host string) (*CertInfo, error) {
	addr := net.JoinHostPort(host, "443")
	if d.Addr != nil {
		addr = d.Addr(host)
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: host,
			// Verification is done by hand below so an expired or mismatched
			// certificate is reported as a finding instead of a dial error.
			InsecureSkipVerify: true, //nolint:gosec // verified manually below
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	info := &CertInfo{NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName, DNSNames: leaf.DNSNames}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: d.Roots})
	info.VerifyOK = verr == nil
	if verr != nil {
		info.VerifyErr = verr.Error()
	}
	return info, nil
}

// --------------------------------------------------------------- security.txt

// SecurityTxt fetches https://host/.well-known/security.txt and returns its
// Contact lines (empty when missing).
func SecurityTxt(ctx context.Context, client *http.Client, baseURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/.well-known/security.txt", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var contacts []string
	for _, ln := range strings.Split(string(body), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToLower(ln), "contact:") {
			contacts = append(contacts, strings.TrimSpace(ln[len("contact:"):]))
		}
	}
	return contacts, nil
}
