// Package bypassfast provides an idiomatic client for the Bypass Fast API.
//
// A Client is safe for concurrent use. It automatically compresses large
// requests, decodes compressed responses, retries explicitly non-billable
// transient API failures, and exposes request IDs for support and tracing.
package bypassfast

import (
	"bytes"
	"compress/gzip"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	// Version is the semantic version of this SDK.
	Version = "0.2.1"

	defaultBaseURL              = "https://api.bypass.fast"
	defaultCompressionThreshold = 1024
	// defaultTimeout bounds one attempt on every route except PerimeterX,
	// just beyond the public edge's 60 s solver deadline. A PerimeterX solve
	// runs a real press-and-hold and may wait in the solver's queue, so the
	// edge allows it 150 s and the SDK follows with a longer per-attempt cap.
	defaultTimeout           = 65 * time.Second
	defaultPerimeterxTimeout = 155 * time.Second
	maxRequestBytes          = 1024 * 1024
	// PerimeterX holdcaptcha bodies carry the customer's HTML block page; the
	// edge and the solver allow 2 MiB for that route only.
	maxPerimeterxRequestBytes = 2 * 1024 * 1024
	maxResponseBytes          = 4 * 1024 * 1024
	maxConfiguredRetries      = 10
	maxRetryDelay             = time.Hour

	defaultSolverBusyRetryBudget = 45 * time.Second
	// solverBusyRetryFloor is the minimum wait when a solver_busy response
	// carries no Retry-After or retry_after_ms hint.
	solverBusyRetryFloor = time.Second
	// solverBusyRetryMaxDelay caps the jitter window of one solver_busy wait.
	solverBusyRetryMaxDelay = 10 * time.Second
)

// Solver identifies a solver accepted by the unified solve endpoint.
type Solver string

const (
	SolverAkamai     Solver = "akamai"
	SolverKasada     Solver = "kasada"
	SolverIncapsula  Solver = "incapsula"
	SolverPerimeterx Solver = "perimeterx"
)

// RetryPolicy controls retries after the API has returned an explicitly
// non-successful response. Transport errors are never retried because the SDK
// cannot know whether the server completed a non-idempotent solve.
type RetryPolicy struct {
	// MaxRetries is the number of retries after the initial attempt. A
	// solver_busy response is instead retried within the solver_busy retry
	// budget (see WithSolverBusyRetryBudget) and does not count against
	// MaxRetries. Zero disables every automatic retry, solver_busy included.
	MaxRetries int
	// BaseDelay is the initial exponential-backoff ceiling.
	BaseDelay time.Duration
	// MaxDelay caps exponential backoff. Retry-After can exceed this value up
	// to the SDK's one-hour safety cap.
	MaxDelay time.Duration
}

type config struct {
	baseURL               string
	httpClient            *http.Client
	timeout               time.Duration
	perimeterxTimeout     time.Duration
	retryPolicy           RetryPolicy
	solverBusyRetryBudget time.Duration
	compressionThreshold  int
	userAgent             string
}

// Option configures a Client.
type Option func(*config) error

// WithBaseURL overrides the API origin. HTTPS is required except for loopback
// development servers.
func WithBaseURL(rawURL string) Option {
	return func(cfg *config) error {
		cfg.baseURL = rawURL
		return nil
	}
}

// WithHTTPClient supplies the HTTP client used for all requests. The Client
// value is copied, while its Transport and Jar remain shared and must not be
// mutated while in use. The per-attempt timeouts (WithTimeout,
// WithPerimeterxTimeout) apply through the request context, so leave the
// client's own Timeout zero unless it should cap PerimeterX solves as well:
// when both are set, the shorter one wins.
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *config) error {
		if client == nil {
			return errors.New("bypassfast: HTTP client must not be nil")
		}
		cfg.httpClient = client
		return nil
	}
}

// WithTimeout sets the per-attempt timeout of every route except PerimeterX.
// The default is 65 seconds, just beyond the public edge's solver deadline.
// It covers connecting, the response headers and the body of one attempt;
// bound a whole call, retries included, with the context.
func WithTimeout(timeout time.Duration) Option {
	return func(cfg *config) error {
		if timeout <= 0 || timeout > maxRetryDelay {
			return fmt.Errorf("bypassfast: timeout must be positive and at most %s", maxRetryDelay)
		}
		cfg.timeout = timeout
		return nil
	}
}

// WithPerimeterxTimeout sets the per-attempt timeout of the PerimeterX
// routes. The default is 155 seconds: a solve runs a real press-and-hold and
// may queue, and the edge allows it 150 seconds.
func WithPerimeterxTimeout(timeout time.Duration) Option {
	return func(cfg *config) error {
		if timeout <= 0 || timeout > maxRetryDelay {
			return fmt.Errorf("bypassfast: PerimeterX timeout must be positive and at most %s", maxRetryDelay)
		}
		cfg.perimeterxTimeout = timeout
		return nil
	}
}

// WithRetryPolicy replaces the default retry policy. Set MaxRetries to zero
// to disable automatic API-response retries.
func WithRetryPolicy(policy RetryPolicy) Option {
	return func(cfg *config) error {
		if policy.MaxRetries < 0 || policy.MaxRetries > maxConfiguredRetries {
			return fmt.Errorf("bypassfast: MaxRetries must be between 0 and %d", maxConfiguredRetries)
		}
		if policy.BaseDelay < 0 || policy.MaxDelay < 0 {
			return errors.New("bypassfast: retry delays must not be negative")
		}
		if policy.BaseDelay > maxRetryDelay || policy.MaxDelay > maxRetryDelay {
			return fmt.Errorf("bypassfast: retry delays must not exceed %s", maxRetryDelay)
		}
		if policy.BaseDelay > 0 && policy.MaxDelay == 0 {
			return errors.New("bypassfast: MaxDelay must be positive when BaseDelay is positive")
		}
		if policy.MaxDelay > 0 && policy.BaseDelay > policy.MaxDelay {
			return errors.New("bypassfast: BaseDelay must not exceed MaxDelay")
		}
		cfg.retryPolicy = policy
		return nil
	}
}

// WithSolverBusyRetryBudget bounds how long the client keeps retrying 429
// solver_busy responses, measured from the start of the call. The default is
// 45 seconds. Each wait honors the server's Retry-After or retry_after_ms hint
// as a floor and adds exponentially growing jitter, and no retry starts after
// the budget or the context deadline. Zero disables solver_busy retries.
func WithSolverBusyRetryBudget(budget time.Duration) Option {
	return func(cfg *config) error {
		if budget < 0 || budget > maxRetryDelay {
			return fmt.Errorf("bypassfast: solver_busy retry budget must be between 0 and %s", maxRetryDelay)
		}
		cfg.solverBusyRetryBudget = budget
		return nil
	}
}

// WithCompressionThreshold controls automatic gzip request compression. A
// negative value disables compression; zero compresses every non-empty body.
func WithCompressionThreshold(bytes int) Option {
	return func(cfg *config) error {
		cfg.compressionThreshold = bytes
		return nil
	}
}

// WithUserAgent adds an application identifier after the SDK user agent.
// For example, "checkout-service/2.4.0" becomes
// "bypassfast-go/0.2.1 checkout-service/2.4.0".
func WithUserAgent(application string) Option {
	return func(cfg *config) error {
		application = strings.TrimSpace(application)
		if application == "" || strings.ContainsAny(application, "\r\n") {
			return errors.New("bypassfast: application user agent is invalid")
		}
		cfg.userAgent += " " + application
		return nil
	}
}

// Client is a concurrency-safe Bypass Fast API client.
type Client struct {
	apiKey                string
	baseURL               string
	httpClient            *http.Client
	timeout               time.Duration
	perimeterxTimeout     time.Duration
	retryPolicy           RetryPolicy
	solverBusyRetryBudget time.Duration
	compressionThreshold  int
	userAgent             string
	scripts               *scriptMemory

	Akamai     *AkamaiService
	Kasada     *KasadaService
	Incapsula  *IncapsulaService
	Perimeterx *PerimeterxService
}

// NewClient constructs a client using an API key. Each attempt is bounded by
// a per-route timeout: 65 seconds by default, just beyond the public edge's
// solver deadline, and 155 seconds for PerimeterX (WithTimeout,
// WithPerimeterxTimeout).
func NewClient(apiKey string, options ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("bypassfast: API key must not be empty")
	}
	if strings.TrimSpace(apiKey) != apiKey || strings.ContainsAny(apiKey, "\r\n") {
		return nil, errors.New("bypassfast: API key contains surrounding or control whitespace")
	}

	cfg := config{
		baseURL:           defaultBaseURL,
		httpClient:        &http.Client{},
		timeout:           defaultTimeout,
		perimeterxTimeout: defaultPerimeterxTimeout,
		retryPolicy: RetryPolicy{
			MaxRetries: 2,
			BaseDelay:  500 * time.Millisecond,
			MaxDelay:   8 * time.Second,
		},
		solverBusyRetryBudget: defaultSolverBusyRetryBudget,
		compressionThreshold:  defaultCompressionThreshold,
		userAgent:             "bypassfast-go/" + Version,
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("bypassfast: option must not be nil")
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}

	baseURL, err := normalizeBaseURL(cfg.baseURL)
	if err != nil {
		return nil, err
	}
	// Refuse redirects even when a caller supplies an HTTP client. Go does not
	// classify X-API-Key as a sensitive header, so its default redirect policy
	// can forward the credential to another origin.
	httpClient := *cfg.httpClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	c := &Client{
		apiKey:                apiKey,
		baseURL:               baseURL,
		httpClient:            &httpClient,
		timeout:               cfg.timeout,
		perimeterxTimeout:     cfg.perimeterxTimeout,
		retryPolicy:           cfg.retryPolicy,
		solverBusyRetryBudget: cfg.solverBusyRetryBudget,
		compressionThreshold:  cfg.compressionThreshold,
		userAgent:             cfg.userAgent,
		scripts:               newScriptMemory(256),
	}
	c.Akamai = &AkamaiService{client: c}
	c.Kasada = &KasadaService{client: c}
	c.Incapsula = &IncapsulaService{client: c}
	c.Perimeterx = &PerimeterxService{client: c}
	return c, nil
}

func normalizeBaseURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("bypassfast: base URL must be an absolute HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("bypassfast: base URL must not contain credentials, query, or fragment")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", errors.New("bypassfast: base URL must use HTTPS unless it is loopback")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Solve invokes a solver with caller-defined request and response types. The
// typed service methods are preferred; Solve exists for forward-compatible or
// advanced fields not yet represented by this SDK.
func (c *Client) Solve(ctx context.Context, solver Solver, request, response any) (ResponseMeta, error) {
	if !solver.valid() {
		return ResponseMeta{}, &ValidationError{Field: "solver", Message: "must be akamai, kasada, incapsula, or perimeterx"}
	}
	if response == nil || reflect.ValueOf(response).Kind() != reflect.Pointer || reflect.ValueOf(response).IsNil() {
		return ResponseMeta{}, &ValidationError{Field: "response", Message: "must be a non-nil pointer"}
	}
	limit, timeout := maxRequestBytes, c.timeout
	if solver == SolverPerimeterx {
		limit, timeout = maxPerimeterxRequestBytes, c.perimeterxTimeout
	}
	return c.doJSONWithLimit(ctx, http.MethodPost, "/v1/solve/"+string(solver), request, response, limit, timeout)
}

func (s Solver) valid() bool {
	switch s {
	case SolverAkamai, SolverKasada, SolverIncapsula, SolverPerimeterx:
		return true
	default:
		return false
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, request, response any) (ResponseMeta, error) {
	return c.doJSONWithLimit(ctx, method, path, request, response, maxRequestBytes, c.timeout)
}

// doJSONWithLimit is doJSON with a route-specific encoded-body cap and
// per-attempt timeout.
func (c *Client) doJSONWithLimit(ctx context.Context, method, path string, request, response any, limit int, timeout time.Duration) (ResponseMeta, error) {
	var payload []byte
	var err error
	if request != nil {
		payload, err = json.Marshal(request)
		if err != nil {
			return ResponseMeta{}, &ValidationError{Field: "request", Message: "could not encode JSON", Cause: err}
		}
		if len(payload) > limit {
			return ResponseMeta{}, &ValidationError{Field: "request", Message: fmt.Sprintf("encoded JSON exceeds the %d MiB API limit", limit/(1024*1024))}
		}
	}

	wirePayload, contentEncoding, err := c.encodeRequest(payload, limit)
	if err != nil {
		return ResponseMeta{}, err
	}
	return c.do(ctx, method, path, wirePayload, contentEncoding, timeout, response)
}

func (c *Client) encodeRequest(payload []byte, limit int) ([]byte, string, error) {
	if len(payload) == 0 || c.compressionThreshold < 0 || len(payload) < c.compressionThreshold {
		return payload, "", nil
	}
	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return nil, "", fmt.Errorf("bypassfast: initialize gzip request: %w", err)
	}
	if _, err = zw.Write(payload); err == nil {
		err = zw.Close()
	} else {
		_ = zw.Close()
	}
	if err != nil {
		return nil, "", fmt.Errorf("bypassfast: compress request: %w", err)
	}
	// Compression is only useful when it reduces bytes, and the edge enforces
	// the same cap on both wire and decoded bodies.
	if compressed.Len() >= len(payload) || compressed.Len() > limit {
		return payload, "", nil
	}
	return compressed.Bytes(), "gzip", nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, contentEncoding string, timeout time.Duration, response any) (ResponseMeta, error) {
	started := time.Now()
	retries, busyRetries := 0, 0
	for attempt := 1; ; attempt++ {
		meta, payload, err := c.attempt(ctx, method, path, body, contentEncoding, timeout, attempt)
		if err == nil {
			if response == nil || len(payload) == 0 {
				return meta, nil
			}
			if err := json.Unmarshal(payload, response); err != nil {
				return meta, &ResponseError{Response: meta, Cause: err}
			}
			return meta, nil
		}

		var apiErr *APIError
		if !errors.As(err, &apiErr) || !apiErr.Retryable() {
			return meta, err
		}
		var delay time.Duration
		if apiErr.Code == "solver_busy" {
			// A task at its admission limit frees slots as solves finish or
			// the fleet scales, so capacity rejects are retried against a time
			// budget; a short synchronized burst would only deepen the overload.
			busyRetries++
			elapsed := time.Since(started)
			delay = solverBusyDelay(busyRetries, apiErr.RetryAfter, c.solverBusyRetryBudget-elapsed, fullJitter)
			if !c.solverBusyRetryFits(ctx, elapsed, delay) {
				return meta, err
			}
		} else {
			if retries >= c.retryPolicy.MaxRetries {
				return meta, err
			}
			// Internal errors are documented for one retry; avoid turning a broken
			// solver release into three identical expensive attempts.
			if retries >= 1 && (apiErr.Code == "internal" || apiErr.Code == "internal_error") {
				return meta, err
			}
			retries++
			delay = c.retryDelay(retries, apiErr.RetryAfter)
		}
		if delay <= 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return meta, ctx.Err()
		case <-timer.C:
		}
	}
}

// attempt performs one HTTP exchange. timeout bounds the whole exchange,
// response body included, on top of the caller's context.
func (c *Client) attempt(ctx context.Context, method, path string, body []byte, contentEncoding string, timeout time.Duration, attempt int) (ResponseMeta, []byte, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return ResponseMeta{}, nil, &RequestError{Operation: "build request", Cause: err}
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if contentEncoding != "" {
			req.Header.Set("Content-Encoding", contentEncoding)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ResponseMeta{Attempts: attempt}, nil, &RequestError{Operation: method + " " + path, Cause: err}
	}
	defer resp.Body.Close()

	meta := ResponseMeta{
		StatusCode:   resp.StatusCode,
		RequestID:    resp.Header.Get("X-Request-ID"),
		Edge:         resp.Header.Get("X-BypassFast-Edge"),
		ServerTiming: resp.Header.Get("Server-Timing"),
		Attempts:     attempt,
	}
	payload, err := readResponse(resp)
	if err != nil {
		return meta, nil, &ResponseError{Response: meta, Cause: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return meta, payload, nil
	}

	apiErr := decodeAPIError(payload)
	apiErr.Response = meta
	// retry_after_ms is the millisecond-precision form of Retry-After; older
	// servers send only the header.
	if apiErr.RetryAfter <= 0 {
		apiErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return meta, nil, apiErr
}

func readResponse(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decode gzip response: %w", err)
		}
		defer zr.Close()
		reader = zr
	default:
		return nil, fmt.Errorf("unsupported response content encoding %q", encoding)
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(payload) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	return payload, nil
}

func (c *Client) retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	base := c.retryPolicy.BaseDelay
	if attempt > 1 && base > 0 {
		for i := 1; i < attempt && base < c.retryPolicy.MaxDelay; i++ {
			if base > c.retryPolicy.MaxDelay/2 {
				base = c.retryPolicy.MaxDelay
				break
			}
			base *= 2
		}
	}
	if c.retryPolicy.MaxDelay > 0 && base > c.retryPolicy.MaxDelay {
		base = c.retryPolicy.MaxDelay
	}
	base = fullJitter(base)
	if retryAfter > base {
		return retryAfter
	}
	return base
}

// solverBusyDelay returns the wait before a call's nth solver_busy retry. The
// server's hint is a floor that is never undercut; above it, a full
// jitter window doubles per retry up to solverBusyRetryMaxDelay (or twice the
// floor, when that is larger) so clients rejected together do not return
// together. While the floor fits in the remaining retry budget, the window
// is narrowed to end inside it, so a long hint is waited out instead of
// ending the call at once with most of its budget unused.
func solverBusyDelay(retry int, retryAfter, remaining time.Duration, jitter func(time.Duration) time.Duration) time.Duration {
	floor := retryAfter
	if floor <= 0 {
		floor = solverBusyRetryFloor
	}
	if floor >= maxRetryDelay {
		return maxRetryDelay
	}
	limit := min(max(solverBusyRetryMaxDelay, 2*floor), maxRetryDelay)
	ceiling := floor
	for i := 0; i < retry && ceiling < limit; i++ {
		ceiling *= 2
	}
	ceiling = min(ceiling, limit)
	if remaining >= floor {
		ceiling = min(ceiling, remaining)
	}
	return floor + jitter(ceiling-floor)
}

// solverBusyRetryFits reports whether a solver_busy retry after delay, with
// elapsed already spent on the call, would start inside both the retry budget
// and the caller's context deadline.
func (c *Client) solverBusyRetryFits(ctx context.Context, elapsed, delay time.Duration) bool {
	if c.retryPolicy.MaxRetries == 0 || c.solverBusyRetryBudget <= 0 {
		return false
	}
	if elapsed+delay > c.solverBusyRetryBudget {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Add(delay).Before(deadline)
}

func fullJitter(ceiling time.Duration) time.Duration {
	if ceiling <= 0 {
		return 0
	}
	var random [8]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return ceiling / 2
	}
	return time.Duration(binary.LittleEndian.Uint64(random[:]) % uint64(ceiling+1))
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds >= int64(maxRetryDelay/time.Second) {
			return maxRetryDelay
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	delay := when.Sub(now)
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func applyFallbackAttempts(meta *ResponseMeta, err error, prior int) {
	if meta != nil {
		meta.Attempts += prior
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		apiErr.Response.Attempts += prior
	}
	var responseErr *ResponseError
	if errors.As(err, &responseErr) {
		responseErr.Response.Attempts += prior
	}
}
