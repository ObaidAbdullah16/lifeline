// Package ghclient is a small GitHub REST API client built on net/http.
package ghclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrNotFound is returned for HTTP 404.
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned for HTTP 403 when the token cannot see the data.
var ErrForbidden = errors.New("forbidden")

// ErrBadToken is returned for HTTP 401: the token is invalid, expired or revoked.
var ErrBadToken = errors.New("GitHub rejected the token (HTTP 401)")

// ErrRateLimited is returned when GitHub refuses the request because the
// (primary or secondary) API rate limit is used up. It is not a visibility
// problem, so checks report it as an error rather than a skip.
var ErrRateLimited = errors.New("GitHub API rate limit exceeded")

// Client talks to the GitHub API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a client using GITHUB_TOKEN or GH_TOKEN when set.
func New() *Client {
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		tok = os.Getenv("GH_TOKEN")
	}
	base := os.Getenv("GITHUB_API_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Token: tok, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// HasToken reports whether requests are authenticated.
func (c *Client) HasToken() bool { return c.Token != "" }

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "lifeline")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrBadToken
	case rateLimited(resp, body):
		return fmt.Errorf("%w (resets at %s)", ErrRateLimited, resp.Header.Get("X-RateLimit-Reset"))
	case resp.StatusCode == http.StatusForbidden:
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%w: %s %s", ErrForbidden, path, msg)
	case resp.StatusCode >= 300:
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func rateLimited(resp *http.Response, body []byte) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0" ||
		strings.Contains(strings.ToLower(string(body)), "rate limit")
}

// Repo is the subset of repository metadata Lifeline uses.
type Repo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Homepage      string `json:"homepage"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Owner         struct {
		Login string `json:"login"`
		Type  string `json:"type"` // "User" or "Organization"
	} `json:"owner"`
}

// GetRepo fetches repository metadata.
func (c *Client) GetRepo(ctx context.Context, repo string) (*Repo, error) {
	var r Repo
	if err := c.get(ctx, "/repos/"+repo, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Org is organisation metadata. TwoFactorRequired is nil unless the token belongs to an owner.
type Org struct {
	Login             string `json:"login"`
	TwoFactorRequired *bool  `json:"two_factor_requirement_enabled"`
}

// GetOrg fetches organisation metadata.
func (c *Client) GetOrg(ctx context.Context, org string) (*Org, error) {
	var o Org
	if err := c.get(ctx, "/orgs/"+url.PathEscape(org), &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// OrgAdmins lists organisation owners visible to the caller (up to 300).
func (c *Client) OrgAdmins(ctx context.Context, org string) ([]string, error) {
	var out []string
	for page := 1; page <= 3; page++ {
		var members []struct {
			Login string `json:"login"`
		}
		if err := c.get(ctx, fmt.Sprintf("/orgs/%s/members?role=admin&per_page=100&page=%d", url.PathEscape(org), page), &members); err != nil {
			return nil, err
		}
		for _, m := range members {
			out = append(out, m.Login)
		}
		if len(members) < 100 {
			break
		}
	}
	return out, nil
}

// BranchProtected reports the `protected` flag of a branch (classic protection or rulesets).
func (c *Client) BranchProtected(ctx context.Context, repo, branch string) (bool, error) {
	var b struct {
		Protected bool `json:"protected"`
	}
	if err := c.get(ctx, "/repos/"+repo+"/branches/"+url.PathEscape(branch), &b); err != nil {
		return false, err
	}
	return b.Protected, nil
}

// BranchRuleTypes lists the ruleset rule types that apply to a branch.
func (c *Client) BranchRuleTypes(ctx context.Context, repo, branch string) ([]string, error) {
	var rules []struct {
		Type string `json:"type"`
	}
	if err := c.get(ctx, "/repos/"+repo+"/rules/branches/"+url.PathEscape(branch), &rules); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rules {
		out = append(out, r.Type)
	}
	return out, nil
}

// CommitAuthors returns the login (or name) of the author of each commit on
// the default branch since `since`, newest first, up to max commits.
func (c *Client) CommitAuthors(ctx context.Context, repo string, since time.Time, max int) ([]string, error) {
	var out []string
	for page := 1; len(out) < max && page <= 10; page++ {
		var commits []struct {
			Author *struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"author"`
			Commit struct {
				Author struct {
					Name string `json:"name"`
				} `json:"author"`
			} `json:"commit"`
		}
		path := fmt.Sprintf("/repos/%s/commits?per_page=100&page=%d&since=%s", repo, page, since.UTC().Format(time.RFC3339))
		if err := c.get(ctx, path, &commits); err != nil {
			return nil, err
		}
		for _, cm := range commits {
			if cm.Author != nil && cm.Author.Type == "Bot" {
				continue
			}
			name := cm.Commit.Author.Name
			if cm.Author != nil && cm.Author.Login != "" {
				name = cm.Author.Login
			}
			if strings.HasSuffix(name, "[bot]") {
				continue
			}
			out = append(out, name)
		}
		if len(commits) < 100 {
			break
		}
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// Entry is one item of a directory listing.
type Entry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// ListDir lists a directory in the default branch. Missing directory = empty list.
func (c *Client) ListDir(ctx context.Context, repo, path string) ([]Entry, error) {
	var out []Entry
	err := c.get(ctx, "/repos/"+repo+"/contents/"+path, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return out, err
}

// FileText returns the text of a file, or ErrNotFound.
func (c *Client) FileText(ctx context.Context, repo, path string) (string, error) {
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := c.get(ctx, "/repos/"+repo+"/contents/"+path, &f); err != nil {
		return "", err
	}
	if f.Encoding != "base64" {
		return f.Content, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	return string(b), err
}
