package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cli/cli/v2/utils"
	ghAPI "github.com/cli/go-gh/v2/pkg/api"
	ghauth "github.com/cli/go-gh/v2/pkg/auth"
)

type tokenGetter interface {
	ActiveToken(string) (string, string)
	TokenForUser(string, string) (string, string, error)
	RepositoryUser(string, string) string
}

type HTTPClientOptions struct {
	AppVersion         string
	CacheTTL           time.Duration
	Config             tokenGetter
	EnableCache        bool
	Log                io.Writer
	LogColorize        bool
	LogVerboseHTTP     bool
	SkipDefaultHeaders bool
}

func NewHTTPClient(opts HTTPClientOptions) (*http.Client, error) {
	// Provide invalid host, and token values so gh.HTTPClient will not automatically resolve them.
	// The real host and token are inserted at request time.
	clientOpts := ghAPI.ClientOptions{
		Host:               "none",
		AuthToken:          "none",
		LogIgnoreEnv:       true,
		SkipDefaultHeaders: opts.SkipDefaultHeaders,
	}

	debugEnabled, debugValue := utils.IsDebugEnabled()
	if strings.Contains(debugValue, "api") {
		opts.LogVerboseHTTP = true
	}

	if opts.LogVerboseHTTP || debugEnabled {
		clientOpts.Log = opts.Log
		clientOpts.LogColorize = opts.LogColorize
		clientOpts.LogVerboseHTTP = opts.LogVerboseHTTP
	}

	headers := map[string]string{
		userAgent: fmt.Sprintf("GitHub CLI %s", opts.AppVersion),
	}
	clientOpts.Headers = headers

	if opts.EnableCache {
		clientOpts.EnableCache = opts.EnableCache
		clientOpts.CacheTTL = opts.CacheTTL
	}

	client, err := ghAPI.NewHTTPClient(clientOpts)
	if err != nil {
		return nil, err
	}

	if opts.Config != nil {
		client.Transport = AddAuthTokenHeader(client.Transport, opts.Config)
	}

	return client, nil
}

func NewCachedHTTPClient(httpClient *http.Client, ttl time.Duration) *http.Client {
	newClient := *httpClient
	newClient.Transport = AddCacheTTLHeader(httpClient.Transport, ttl)
	return &newClient
}

// AddCacheTTLHeader adds an header to the request telling the cache that the request
// should be cached for a specified amount of time.
func AddCacheTTLHeader(rt http.RoundTripper, ttl time.Duration) http.RoundTripper {
	return &funcTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		// If the header is already set in the request, don't overwrite it.
		if req.Header.Get(cacheTTL) == "" {
			req.Header.Set(cacheTTL, ttl.String())
		}
		return rt.RoundTrip(req)
	}}
}

// AddAuthTokenHeader adds an authentication token header for the host specified by the request.
func AddAuthTokenHeader(rt http.RoundTripper, cfg tokenGetter) http.RoundTripper {
	return &authTokenTripper{base: rt, cfg: cfg}
}

type authTokenTripper struct {
	base http.RoundTripper
	cfg  tokenGetter
}

func (tr *authTokenTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get(authorization) == "" {
		var redirectHostnameChange bool
		if req.Response != nil && req.Response.Request != nil {
			redirectHostnameChange = getHost(req) != getHost(req.Response.Request)
		}
		if !redirectHostnameChange {
			hostname := ghauth.NormalizeHostname(getHost(req))
			if token := tr.resolveToken(req, hostname); token != "" {
				req.Header.Set(authorization, fmt.Sprintf("token %s", token))
			}
		}
	}
	return tr.base.RoundTrip(req)
}

func (tr *authTokenTripper) resolveToken(req *http.Request, hostname string) string {
	slug := inferRepoSlug(req)
	if slug != "" {
		for _, user := range candidateUsersForSlug(tr.cfg, hostname, slug) {
			if token, _, err := tr.cfg.TokenForUser(hostname, user); err == nil && token != "" {
				return token
			}
		}
	}
	token, _ := tr.cfg.ActiveToken(hostname)
	return token
}

func candidateUsersForSlug(cfg tokenGetter, hostname, slug string) []string {
	if slug == "" {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(user string, out *[]string) {
		user = strings.TrimSpace(user)
		if user == "" {
			return
		}
		key := strings.ToLower(user)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*out = append(*out, user)
	}

	candidates := []string{}
	add(cfg.RepositoryUser(hostname, slug), &candidates)
	if owner := ownerFromSlug(slug); owner != "" {
		add(cfg.RepositoryUser(hostname, owner), &candidates)
		add(owner, &candidates)
	}
	return candidates
}

func ownerFromSlug(slug string) string {
	parts := strings.SplitN(slug, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func inferRepoSlug(req *http.Request) string {
	if slug := slugFromRESTPath(req.URL.Path); slug != "" {
		return slug
	}
	if slug := slugFromHeaders(req); slug != "" {
		return slug
	}
	if slug := slugFromGraphQL(req); slug != "" {
		return slug
	}
	return ""
}

func slugFromRESTPath(path string) string {
	if path == "" {
		return ""
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	segments := strings.Split(trimmed, "/")
	for i := 0; i < len(segments); i++ {
		if segments[i] == "repos" && len(segments) > i+2 {
			owner := cleanRepoSegment(segments[i+1])
			repo := cleanRepoSegment(segments[i+2])
			if owner != "" && repo != "" {
				return owner + "/" + repo
			}
		}
	}
	return ""
}

func slugFromHeaders(req *http.Request) string {
	if req == nil {
		return ""
	}
	if slug := req.Header.Get("X-GH-Repository"); slug != "" {
		return canonicalizeSlug(slug)
	}
	return ""
}

func slugFromGraphQL(req *http.Request) string {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return ""
	}
	if !strings.HasSuffix(strings.TrimRight(req.URL.Path, "/"), "graphql") {
		return ""
	}
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "application/json") {
		return ""
	}

	payloadBytes, err := readAndRestoreBody(req)
	if err != nil || len(payloadBytes) == 0 {
		return ""
	}

	var payload struct {
		Variables map[string]interface{} `json:"variables"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ""
	}

	vars := payload.Variables
	if vars == nil {
		return ""
	}

	owner := firstString(vars, []string{"owner", "repositoryOwner", "organization", "org"})
	name := firstString(vars, []string{"name", "repositoryName"})
	if owner != "" && name != "" {
		return canonicalizeSlug(owner + "/" + name)
	}

	if slug := firstString(vars, []string{"nameWithOwner", "repository", "repositoryWithOwner", "repo"}); slug != "" {
		if strings.Contains(slug, "/") {
			return canonicalizeSlug(slug)
		}
	}

	return ""
}

func readAndRestoreBody(req *http.Request) ([]byte, error) {
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if err := req.Body.Close(); err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if req.GetBody != nil {
		captured := append([]byte(nil), bodyBytes...)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(captured)), nil
		}
	}
	return bodyBytes, nil
}

func firstString(m map[string]interface{}, keys []string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			switch v := val.(type) {
			case string:
				if v != "" {
					return v
				}
			case map[string]interface{}:
				if nested := firstString(v, keys); nested != "" {
					return nested
				}
			}
		}
	}
	return ""
}

func canonicalizeSlug(slug string) string {
	slug = strings.Trim(slug, "/")
	if slug == "" {
		return ""
	}
	parts := strings.SplitN(slug, "/", 3)
	if len(parts) < 2 {
		return cleanRepoSegment(parts[0])
	}
	owner := cleanRepoSegment(parts[0])
	repo := cleanRepoSegment(parts[1])
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

func cleanRepoSegment(segment string) string {
	if segment == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(segment); err == nil {
		segment = decoded
	}
	segment = strings.TrimSpace(segment)
	segment = strings.Trim(segment, "/")
	segment = strings.TrimSuffix(segment, ".git")
	return segment
}

// ExtractHeader extracts a named header from any response received by this client and,
// if non-blank, saves it to dest.
func ExtractHeader(name string, dest *string) func(http.RoundTripper) http.RoundTripper {
	return func(tr http.RoundTripper) http.RoundTripper {
		return &funcTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
			res, err := tr.RoundTrip(req)
			if err == nil {
				if value := res.Header.Get(name); value != "" {
					*dest = value
				}
			}
			return res, err
		}}
	}
}

type funcTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (tr funcTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return tr.roundTrip(req)
}

func getHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}
