package forge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Client is a minimal typed Forgejo (Gitea-compatible /api/v1) client.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

func NewClient(base, token string) *Client {
	return &Client{base: strings.TrimRight(base, "/") + "/api/v1", token: token, hc: &http.Client{Timeout: 10 * time.Second}}
}

// HTTPError is a non-2xx reply from Forgejo.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("forgejo %d: %s", e.Status, e.Body) }

func isStatus(err error, code int) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == code
}

// apiErr maps a client error onto the wire: 404 -> notfound, anything else -> 503 frozen forge-unavailable.
func apiErr(err error) error {
	if err == nil {
		return nil
	}
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae
	}
	if isStatus(err, 404) {
		return core.ErrNotFound
	}
	return core.E(503, "frozen", "forge-unavailable")
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		s := strings.TrimSpace(string(rb))
		if len(s) > 200 {
			s = s[:200]
		}
		return &HTTPError{res.StatusCode, s}
	}
	if out != nil && len(bytes.TrimSpace(rb)) > 0 {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// --- orgs / repos ---

type Org struct {
	ID         int64  `json:"id"`
	Name       string `json:"username"`
	Visibility string `json:"visibility,omitempty"`
}

func (c *Client) GetOrg(ctx context.Context, name string) (*Org, error) {
	var o Org
	if err := c.do(ctx, "GET", "/orgs/"+url.PathEscape(name), nil, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func (c *Client) CreateOrg(ctx context.Context, name string) (*Org, error) {
	var o Org
	in := map[string]any{"username": name, "visibility": "public", "repo_admin_change_team_access": false}
	if err := c.do(ctx, "POST", "/orgs", in, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

type Repo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	FullName  string `json:"full_name"`
	HasIssues bool   `json:"has_issues"`
	HasWiki   bool   `json:"has_wiki"`
	Size      int64  `json:"size"` // KiB
}

// RepoOpts selects the features kept on; everything else (PRs, projects, releases, packages, actions) is disabled.
type RepoOpts struct {
	Issues, Wiki, AutoInit bool
}

func (c *Client) GetRepo(ctx context.Context, owner, repo string) (*Repo, error) {
	var r Repo
	if err := c.do(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) CreateOrgRepo(ctx context.Context, org, name string, o RepoOpts) (*Repo, error) {
	var r Repo
	in := map[string]any{"name": name, "private": false, "auto_init": o.AutoInit, "default_branch": "main"}
	if err := c.do(ctx, "POST", "/orgs/"+url.PathEscape(org)+"/repos", in, &r); err != nil {
		return nil, err
	}
	return &r, c.EditRepo(ctx, org, name, o)
}

func (c *Client) EditRepo(ctx context.Context, owner, repo string, o RepoOpts) error {
	in := map[string]any{
		"has_issues": o.Issues, "has_wiki": o.Wiki,
		"has_pull_requests": false, "has_projects": false, "has_releases": false,
		"has_packages": false, "has_actions": false,
	}
	return c.do(ctx, "PATCH", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo), in, nil)
}

// --- labels ---

type Label struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

func (c *Client) ListLabels(ctx context.Context, owner, repo string) ([]Label, error) {
	var out []Label
	for page := 1; page < 20; page++ {
		var ls []Label
		p := fmt.Sprintf("/repos/%s/%s/labels?page=%d&limit=50", url.PathEscape(owner), url.PathEscape(repo), page)
		if err := c.do(ctx, "GET", p, nil, &ls); err != nil {
			return nil, err
		}
		out = append(out, ls...)
		if len(ls) < 50 {
			break
		}
	}
	return out, nil
}

func (c *Client) CreateLabel(ctx context.Context, owner, repo, name, color string) (*Label, error) {
	var l Label
	in := map[string]any{"name": name, "color": color}
	if err := c.do(ctx, "POST", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/labels", in, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// --- issues ---

type Issue struct {
	Number   int64     `json:"number"`
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	State    string    `json:"state"`
	Labels   []Label   `json:"labels"`
	Created  time.Time `json:"created_at"`
	Updated  time.Time `json:"updated_at"`
	Comments int       `json:"comments"`
}

func (i *Issue) HasLabel(name string) bool {
	for _, l := range i.Labels {
		if l.Name == name {
			return true
		}
	}
	return false
}

type IssueQuery struct {
	State  string // open|closed|all
	Labels []string
	Q      string
	Limit  int
	Page   int
}

func (c *Client) ListIssues(ctx context.Context, owner, repo string, q IssueQuery) ([]Issue, error) {
	v := url.Values{}
	v.Set("type", "issues")
	if q.State != "" {
		v.Set("state", q.State)
	}
	if len(q.Labels) > 0 {
		v.Set("labels", strings.Join(q.Labels, ","))
	}
	if q.Q != "" {
		v.Set("q", q.Q)
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Page > 0 {
		v.Set("page", strconv.Itoa(q.Page))
	}
	var out []Issue
	err := c.do(ctx, "GET", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues?"+v.Encode(), nil, &out)
	return out, err
}

func (c *Client) GetIssue(ctx context.Context, owner, repo string, n int64) (*Issue, error) {
	var i Issue
	if err := c.do(ctx, "GET", fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), n), nil, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

func (c *Client) CreateIssue(ctx context.Context, owner, repo, title, body string, labels []int64) (*Issue, error) {
	var i Issue
	in := map[string]any{"title": title, "body": body}
	if len(labels) > 0 {
		in["labels"] = labels
	}
	if err := c.do(ctx, "POST", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues", in, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

// EditIssue patches state ("open"/"closed") and/or body; empty strings leave the field alone.
func (c *Client) EditIssue(ctx context.Context, owner, repo string, n int64, state, body string) error {
	return c.EditIssueFull(ctx, owner, repo, n, "", state, body)
}

// EditIssueFull patches title, state and body; empty strings leave the field alone.
func (c *Client) EditIssueFull(ctx context.Context, owner, repo string, n int64, title, state, body string) error {
	in := map[string]any{}
	if title != "" {
		in["title"] = title
	}
	if state != "" {
		in["state"] = state
	}
	if body != "" {
		in["body"] = body
	}
	return c.do(ctx, "PATCH", fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), n), in, nil)
}

type Comment struct {
	ID      int64     `json:"id"`
	Body    string    `json:"body"`
	Created time.Time `json:"created_at"`
}

func (c *Client) ListComments(ctx context.Context, owner, repo string, n int64) ([]Comment, error) {
	var out []Comment
	err := c.do(ctx, "GET", fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), n), nil, &out)
	return out, err
}

func (c *Client) CreateComment(ctx context.Context, owner, repo string, n int64, body string) (*Comment, error) {
	var cm Comment
	err := c.do(ctx, "POST", fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), n), map[string]string{"body": body}, &cm)
	if err != nil {
		return nil, err
	}
	return &cm, nil
}

func (c *Client) AddIssueLabels(ctx context.Context, owner, repo string, n int64, ids []int64) error {
	return c.do(ctx, "POST", fmt.Sprintf("/repos/%s/%s/issues/%d/labels", url.PathEscape(owner), url.PathEscape(repo), n), map[string]any{"labels": ids}, nil)
}

func (c *Client) RemoveIssueLabel(ctx context.Context, owner, repo string, n, id int64) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/repos/%s/%s/issues/%d/labels/%d", url.PathEscape(owner), url.PathEscape(repo), n, id), nil, nil)
}

// --- wiki ---

type WikiPage struct {
	Title   string `json:"title"`
	Content string `json:"content_base64"`
}

func (p *WikiPage) Text() string {
	b, err := base64.StdEncoding.DecodeString(p.Content)
	if err != nil {
		return ""
	}
	return string(b)
}

// wikiPath escapes '-' as %2D: Forgejo maps a literal '-' in a wiki web path to a space,
// so "a--b" would resolve to the page "a  b" (404) instead of the page titled "a--b".
func wikiPath(owner, repo, page string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/wiki/page/" + strings.ReplaceAll(url.PathEscape(page), "-", "%2D")
}

func (c *Client) GetWiki(ctx context.Context, owner, repo, page string) (*WikiPage, error) {
	var p WikiPage
	if err := c.do(ctx, "GET", wikiPath(owner, repo, page), nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) CreateWiki(ctx context.Context, owner, repo, page, text string) error {
	in := map[string]string{"title": page, "content_base64": base64.StdEncoding.EncodeToString([]byte(text)), "message": "note"}
	return c.do(ctx, "POST", "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/wiki/new", in, nil)
}

func (c *Client) EditWiki(ctx context.Context, owner, repo, page, text string) error {
	in := map[string]string{"title": page, "content_base64": base64.StdEncoding.EncodeToString([]byte(text)), "message": "note"}
	return c.do(ctx, "PATCH", wikiPath(owner, repo, page), in, nil)
}

func (c *Client) DeleteWiki(ctx context.Context, owner, repo, page string) error {
	return c.do(ctx, "DELETE", wikiPath(owner, repo, page), nil, nil)
}

// PutWiki creates the page or edits it when it already exists.
func (c *Client) PutWiki(ctx context.Context, owner, repo, page, text string) error {
	err := c.CreateWiki(ctx, owner, repo, page, text)
	// Forgejo 15 answers 400 "wiki page already exists" (older Gitea: 409).
	if err == nil || !(isStatus(err, 409) || isStatus(err, 400)) {
		return err
	}
	return c.EditWiki(ctx, owner, repo, page, text)
}

func (c *Client) ListWiki(ctx context.Context, owner, repo string) ([]WikiPage, error) {
	var out []WikiPage
	for page := 1; page < 100; page++ {
		var ps []WikiPage
		p := fmt.Sprintf("/repos/%s/%s/wiki/pages?page=%d&limit=50", url.PathEscape(owner), url.PathEscape(repo), page)
		if err := c.do(ctx, "GET", p, nil, &ps); err != nil {
			return nil, err
		}
		out = append(out, ps...)
		if len(ps) < 50 {
			break
		}
	}
	return out, nil
}

// --- repo contents ---

type Content struct {
	SHA string `json:"sha"`
}

func contentsPath(owner, repo, path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/contents/" + strings.Join(parts, "/")
}

func (c *Client) GetContent(ctx context.Context, owner, repo, path string) (*Content, error) {
	var ct Content
	if err := c.do(ctx, "GET", contentsPath(owner, repo, path), nil, &ct); err != nil {
		return nil, err
	}
	return &ct, nil
}

// DeleteFile removes path (fetches the current sha); a missing file is not an error.
func (c *Client) DeleteFile(ctx context.Context, owner, repo, path, msg string) error {
	cur, err := c.GetContent(ctx, owner, repo, path)
	if isStatus(err, 404) {
		return nil
	}
	if err != nil {
		return err
	}
	err = c.do(ctx, "DELETE", contentsPath(owner, repo, path), map[string]string{"sha": cur.SHA, "message": msg}, nil)
	if isStatus(err, 404) {
		return nil
	}
	return err
}

// PutFile creates or updates path with data (fetches the current sha for updates).
func (c *Client) PutFile(ctx context.Context, owner, repo, path string, data []byte, msg string) error {
	in := map[string]string{"content": base64.StdEncoding.EncodeToString(data), "message": msg}
	cur, err := c.GetContent(ctx, owner, repo, path)
	switch {
	case err == nil:
		in["sha"] = cur.SHA
		return c.do(ctx, "PUT", contentsPath(owner, repo, path), in, nil)
	case isStatus(err, 404):
		return c.do(ctx, "POST", contentsPath(owner, repo, path), in, nil)
	default:
		return err
	}
}
