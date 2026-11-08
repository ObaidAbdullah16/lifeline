# Email and domain security add-on: the staged runbook

An add-on sold to small businesses, agencies and startups alongside S2, S7 or S8:
**$49-99 founding (₹2-5k)** for the fix, **$150-300** with the staged move to `p=reject` and monitoring.
Google and Yahoo require SPF, DKIM and DMARC from bulk senders, Microsoft's consumer mailboxes followed in
2025, and most domains still cannot reject spoofed mail. The cheap version of this service breaks
legitimate email; this runbook is the careful version.

> Work only on domains the client owns, from public DNS, and change records only in the client's DNS console
> with the client (or with written authorisation). Nothing here sends test mail as the client.

## Day 0 - before score (no access needed)

```bash
lifeline scan --domain client.com --format md > before.md
```

Expiry (LL-DOM-001), TLS (002), CAA (003), DNSSEC (004), SPF/DMARC (005), DKIM (006), SPF lookups (007).

## Day 1 - inventory every sender

Ask, then confirm in the mail headers of a real message from each: Google Workspace or Microsoft 365, the
website's contact form (often the hosting server), invoicing tool, CRM, newsletter, helpdesk, transactional email
(SES, SendGrid, Postmark), payroll. Missing one sender is how DMARC enforcement loses real mail.

| Sender | Sends as | SPF mechanism | DKIM selector | Owner |
|---|---|---|---|---|
| Google Workspace | @client.com | `include:_spf.google.com` | `google` | |
| {tool} | {address} | {include} | {selector} | |

## Day 1 - fix SPF and DKIM

- **One** SPF record: `v=spf1 include:_spf.google.com include:{other} -all` (or `~all` while unsure).
  No `+all`, no second SPF record, at most 10 DNS lookups (LL-DOM-007).
- Domains that never send mail: `v=spf1 -all`, `v=DMARC1; p=reject;` and a null MX (`0 .`).
- DKIM: turn on signing in **each** sender and publish its key (2048-bit where offered). Note each selector in
  lifeline.yml (`dkim_selectors:`).

## Day 1 - DMARC in monitoring mode

```
_dmarc.client.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@client.com; fo=1"
```

Use a mailbox (or a free DMARC report service) the client controls. Reports arrive daily as XML from Google,
Microsoft and others.

## Weeks 1-4 - read the reports, stage enforcement

| When | Record | Move on when |
|---|---|---|
| Week 0 | `p=none` | Every legitimate sender passes SPF or DKIM **aligned** with the domain |
| Week 2-3 | `p=quarantine; pct=25` then `pct=100` | No legitimate mail in quarantine for a week |
| Week 4-8 | `p=reject` | Done; keep `rua` so new senders show up |

A sender that fails alignment is fixed at the sender (custom DKIM, custom MAIL FROM), never by loosening DMARC.

## Same visit - the rest of the domain

- **CAA:** `client.com. CAA 0 issue "letsencrypt.org"` (plus the CA of any other certificate in use).
- **Expiry:** auto-renew on, renewal for several years, two people with registrar access, registrar 2FA.
- **TLS:** automated renewal and an alert at 14 days (most hosts and CDNs do this; check it).
- **DNSSEC:** where the registrar and DNS host support it (optional; a broken chain is worse than none).

## Close - after score and care

```bash
lifeline scan --domain client.com --format md > after.md
```

Send both scores. Offer monitoring: Lifeline in a scheduled GitHub Action (see the README) alerts on expiry,
certificate and DMARC regressions; review DMARC reports monthly as part of a care plan.
