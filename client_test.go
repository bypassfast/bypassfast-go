package bypassfast

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCompressesRequestsAndDecodesResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/solve/kasada" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			t.Errorf("X-API-Key = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "bypassfast-go/"+Version+" checkout/1.0" {
			t.Errorf("User-Agent = %q", got)
		}
		if r.ContentLength <= 0 || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("content length/encoding = %d/%q", r.ContentLength, r.Header.Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestBody, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		var request map[string]any
		if err := json.Unmarshal(requestBody, &request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request["mode"] != "sensor" || request["accept_language"] != "en-US" {
			t.Errorf("request body = %#v", request)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Request-ID", "req-123")
		w.Header().Set("X-BypassFast-Edge", "edge-v1")
		w.Header().Set("Server-Timing", "solve;dur=12")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(`{"cost":0.002,"payload":"cipher","user_agent":"ua-out","duration_ms":12}`))
		_ = zw.Close()
	}))
	defer server.Close()

	client := newTestClient(t, server, WithUserAgent("checkout/1.0"))
	result, err := client.Kasada.Sensor(context.Background(), &KasadaSensorRequest{
		Script:         strings.Repeat("var challenge = 1;", 200),
		UserAgent:      "ua-in",
		AcceptLanguage: "en-US",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Payload != "cipher" || result.Cost != 0.002 || result.UserAgent != "ua-out" {
		t.Fatalf("result = %#v", result)
	}
	if result.Response != (ResponseMeta{StatusCode: 200, RequestID: "req-123", Edge: "edge-v1", ServerTiming: "solve;dur=12", Attempts: 1}) {
		t.Fatalf("metadata = %#v", result.Response)
	}
}

func TestAPIErrorSupportsBothEnvelopes(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		code string
	}{
		{name: "standard", body: `{"error":"domain_not_allowed","message":"target is not allowed"}`, code: "domain_not_allowed"},
		{name: "akamai", body: `{"success":false,"error_code":"unsupported_script","message":"fresh script required","stage":"extract"}`, code: "unsupported_script"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Request-ID", "req-error")
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := newTestClient(t, server)

			_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %T %v", err, err)
			}
			if apiErr.Code != test.code || apiErr.Response.RequestID != "req-error" || !IsErrorCode(err, test.code) {
				t.Fatalf("API error = %#v", apiErr)
			}
			if test.name == "akamai" && apiErr.Stage != "extract" {
				t.Fatalf("stage = %q", apiErr.Stage)
			}
		})
	}
}

func TestMalformedResponseErrorsDoNotExposeBodies(t *testing.T) {
	const secret = "cookie-secret-must-not-appear"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "req-malformed")
		_, _ = io.WriteString(w, `{"cookie":"`+secret+`")`)
	}))
	defer server.Close()
	client := newTestClient(t, server)

	_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) || responseErr.Response.RequestID != "req-malformed" {
		t.Fatalf("error = %T %v", err, err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed response body: %v", err)
	}

	apiErr := &APIError{Code: "bad_request", Message: secret, Response: ResponseMeta{StatusCode: 400}}
	if strings.Contains(apiErr.Error(), secret) {
		t.Fatalf("API error exposed human message: %v", apiErr)
	}
}

func TestRetriesOnlyExplicitRetryableResponses(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"solver_unavailable"}`)
			return
		}
		_, _ = io.WriteString(w, `{"payload":"ok","duration_ms":1}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 2}))

	result, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || result.Response.Attempts != 2 {
		t.Fatalf("calls/attempts = %d/%d", calls.Load(), result.Response.Attempts)
	}

	calls.Store(0)
	quotaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"quota_exceeded"}`)
	}))
	defer quotaServer.Close()
	quotaClient := newTestClient(t, quotaServer, WithRetryPolicy(RetryPolicy{MaxRetries: 2}))
	_, err = quotaClient.Kasada.CD(context.Background(), &KasadaCDRequest{})
	if !IsErrorCode(err, "quota_exceeded") || calls.Load() != 1 {
		t.Fatalf("quota error/calls = %v/%d", err, calls.Load())
	}

	calls.Store(0)
	exhaustedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"solver_unavailable"}`)
	}))
	defer exhaustedServer.Close()
	exhaustedClient := newTestClient(t, exhaustedServer, WithRetryPolicy(RetryPolicy{MaxRetries: 2}))
	_, err = exhaustedClient.Kasada.CD(context.Background(), &KasadaCDRequest{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || calls.Load() != 3 || apiErr.Response.Attempts != 3 {
		t.Fatalf("exhausted error/calls = %#v/%d", apiErr, calls.Load())
	}
}

func TestTransportErrorsAreNotRetried(t *testing.T) {
	var calls atomic.Int32
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("connection reset")
	})}
	client, err := NewClient("test-key", WithHTTPClient(httpClient), WithRetryPolicy(RetryPolicy{MaxRetries: 5}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	var requestErr *RequestError
	if !errors.As(err, &requestErr) || calls.Load() != 1 {
		t.Fatalf("error/calls = %T %v/%d", err, err, calls.Load())
	}
}

func TestRetryWaitHonorsContextCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"solver_unavailable"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{
		MaxRetries: 2,
		BaseDelay:  time.Second,
		MaxDelay:   time.Second,
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Kasada.CD(ctx, &KasadaCDRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
}

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"payload":"ok","backend":"replay"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	request := &IncapsulaReese84Request{
		Script:    "shared script",
		ScriptURL: "https://example.com/loader.js",
		URL:       "https://example.com",
		UserAgent: "ua",
	}

	var wg sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Incapsula.Reese84(context.Background(), request)
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRedirectsCannotForwardAPIKey(t *testing.T) {
	var redirectedCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client := newTestClient(t, origin)

	_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("error = %T %v", err, err)
	}
	if redirectedCalls.Load() != 0 {
		t.Fatalf("redirect destination received %d requests", redirectedCalls.Load())
	}
}

func TestBalanceAndGenericSolve(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/balance":
			if r.Method != http.MethodGet || r.Body != http.NoBody {
				t.Errorf("balance request = %s body=%T", r.Method, r.Body)
			}
			_, _ = io.WriteString(w, `{"errorId":0,"org_id":"org_1","balance":12.5,"balance_cents":1250,"currency":"USD"}`)
		case "/v1/solve/akamai":
			_, _ = io.WriteString(w, `{"success":true,"answers":["a"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)

	balance, err := client.Balance(context.Background())
	if err != nil || balance.AmountCents != 1250 || balance.Currency != "USD" {
		t.Fatalf("balance/error = %#v/%v", balance, err)
	}
	var response struct {
		Answers []string `json:"answers"`
	}
	meta, err := client.Solve(context.Background(), SolverAkamai, map[string]any{"mode": "cpt"}, &response)
	if err != nil || len(response.Answers) != 1 || meta.Attempts != 1 || calls.Load() != 2 {
		t.Fatalf("generic response/meta/error/calls = %#v/%#v/%v/%d", response, meta, err, calls.Load())
	}
}

func TestClientValidation(t *testing.T) {
	if _, err := NewClient(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := NewClient(" key "); err == nil {
		t.Fatal("whitespace key accepted")
	}
	if _, err := NewClient("key", WithBaseURL("http://example.com")); err == nil {
		t.Fatal("non-TLS remote URL accepted")
	}
	if _, err := NewClient("key", WithRetryPolicy(RetryPolicy{MaxRetries: -1})); err == nil {
		t.Fatal("negative retries accepted")
	}
	if _, err := NewClient("key", WithRetryPolicy(RetryPolicy{MaxRetries: 1, BaseDelay: time.Second})); err == nil {
		t.Fatal("uncapped positive retry delay accepted")
	}
	if _, err := NewClient("key", WithSolverBusyRetryBudget(-time.Second)); err == nil {
		t.Fatal("negative solver_busy retry budget accepted")
	}
	if _, err := NewClient("key", WithSolverBusyRetryBudget(2*time.Hour)); err == nil {
		t.Fatal("oversized solver_busy retry budget accepted")
	}
	client, err := NewClient("key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Solve(context.Background(), Solver("../admin"), struct{}{}, &struct{}{}); err == nil {
		t.Fatal("invalid solver accepted")
	}
	var nilResponse *struct{}
	if _, err := client.Solve(context.Background(), SolverAkamai, struct{}{}, nilResponse); err == nil {
		t.Fatal("typed nil response accepted")
	}
}

func TestRequestBodyLimitIsLocal(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newTestClient(t, server)
	_, err := client.Kasada.Sensor(context.Background(), &KasadaSensorRequest{Script: strings.Repeat("x", maxRequestBytes+1)})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || calls.Load() != 0 {
		t.Fatalf("error/calls = %T %v/%d", err, err, calls.Load())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("2", now); got != 2*time.Second {
		t.Fatalf("seconds = %s", got)
	}
	if got := parseRetryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now); got != 3*time.Second {
		t.Fatalf("date = %s", got)
	}
	if got := parseRetryAfter("9223372036854775807", now); got != maxRetryDelay {
		t.Fatalf("large delay = %s", got)
	}
}

func TestSolverBusyDelayBounds(t *testing.T) {
	low := func(time.Duration) time.Duration { return 0 }
	high := func(window time.Duration) time.Duration { return window }
	for _, test := range []struct {
		name       string
		retry      int
		retryAfter time.Duration
		remaining  time.Duration
		min, max   time.Duration
	}{
		{name: "no hint uses the one-second floor", retry: 1, min: time.Second, max: 2 * time.Second},
		{name: "window doubles", retry: 2, retryAfter: time.Second, min: time.Second, max: 4 * time.Second},
		{name: "third retry", retry: 3, retryAfter: time.Second, min: time.Second, max: 8 * time.Second},
		{name: "window caps at ten seconds", retry: 4, retryAfter: time.Second, min: time.Second, max: 10 * time.Second},
		{name: "cap holds for long streaks", retry: 60, retryAfter: time.Second, min: time.Second, max: 10 * time.Second},
		{name: "millisecond hint is the floor", retry: 1, retryAfter: 250 * time.Millisecond, min: 250 * time.Millisecond, max: 500 * time.Millisecond},
		{name: "small hint still reaches the cap", retry: 8, retryAfter: 250 * time.Millisecond, min: 250 * time.Millisecond, max: 10 * time.Second},
		{name: "hint above the cap keeps a jitter window", retry: 3, retryAfter: 20 * time.Second, min: 20 * time.Second, max: 40 * time.Second},
		{name: "safety cap", retry: 1, retryAfter: 2 * time.Hour, min: maxRetryDelay, max: maxRetryDelay},
		{name: "window narrows to the remaining budget", retry: 1, retryAfter: 30 * time.Second, remaining: 40 * time.Second, min: 30 * time.Second, max: 40 * time.Second},
		{name: "floor exactly fills the remaining budget", retry: 2, retryAfter: 5 * time.Second, remaining: 5 * time.Second, min: 5 * time.Second, max: 5 * time.Second},
		{name: "floor beyond the remaining budget is not undercut", retry: 1, retryAfter: 30 * time.Second, remaining: 10 * time.Second, min: 30 * time.Second, max: 60 * time.Second},
		{name: "spent budget keeps the full window", retry: 1, remaining: -time.Second, min: time.Second, max: 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			remaining := test.remaining
			if remaining == 0 {
				remaining = maxRetryDelay
			}
			if got := solverBusyDelay(test.retry, test.retryAfter, remaining, low); got != test.min {
				t.Fatalf("minimum = %s, want %s", got, test.min)
			}
			if got := solverBusyDelay(test.retry, test.retryAfter, remaining, high); got != test.max {
				t.Fatalf("maximum = %s, want %s", got, test.max)
			}
			for i := 0; i < 200; i++ {
				if got := solverBusyDelay(test.retry, test.retryAfter, remaining, fullJitter); got < test.min || got > test.max {
					t.Fatalf("jittered delay %s outside [%s, %s]", got, test.min, test.max)
				}
			}
		})
	}
}

func TestSolverBusyRetriesDoNotConsumeMaxRetries(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 3 {
			// The header alone would force a one-second wait; the body hint
			// is authoritative when present.
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":1}`)
			return
		}
		_, _ = io.WriteString(w, `{"payload":"ok","duration_ms":1}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 1}))

	started := time.Now()
	result, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 || result.Response.Attempts != 4 {
		t.Fatalf("calls/attempts = %d/%d", calls.Load(), result.Response.Attempts)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("retries took %s; retry_after_ms was not preferred over Retry-After", elapsed)
	}
}

func TestSolverBusyRetryBudgetExhaustion(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":5}`)
	}))
	defer server.Close()
	const budget = 200 * time.Millisecond
	client := newTestClient(t, server,
		WithRetryPolicy(RetryPolicy{MaxRetries: 1}),
		WithSolverBusyRetryBudget(budget))

	started := time.Now()
	_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	elapsed := time.Since(started)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "solver_busy" {
		t.Fatalf("error = %T %v", err, err)
	}
	// The first two waits total at most 30 ms, so a 200 ms budget always
	// allows more attempts than MaxRetries would.
	if calls.Load() < 3 || apiErr.Response.Attempts != int(calls.Load()) {
		t.Fatalf("calls/attempts = %d/%d", calls.Load(), apiErr.Response.Attempts)
	}
	if apiErr.RetryAfter != 5*time.Millisecond {
		t.Fatalf("retry after = %s", apiErr.RetryAfter)
	}
	// No retry starts after the budget; allow for the last request itself.
	if elapsed > budget+time.Second {
		t.Fatalf("elapsed %s exceeded the %s budget", elapsed, budget)
	}
}

func TestSolverBusyLongHintRetriesWithinBudget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1)%2 == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":300}`)
			return
		}
		_, _ = io.WriteString(w, `{"payload":"ok","duration_ms":1}`)
	}))
	defer server.Close()
	client := newTestClient(t, server,
		WithRetryPolicy(RetryPolicy{MaxRetries: 1}),
		WithSolverBusyRetryBudget(500*time.Millisecond))

	// The hint fits the budget but its doubled jitter window does not; the
	// wait must be drawn inside the budget rather than ending the call with
	// most of the budget unused.
	for i := 0; i < 5; i++ {
		result, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if result.Response.Attempts != 2 {
			t.Fatalf("call %d attempts = %d", i, result.Response.Attempts)
		}
	}
}

func TestSolverBusyRetryStopsBeforeContextDeadline(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":2000}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 1}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// A retry that cannot start before the deadline is not waited for: the
	// caller gets the capacity error rather than a context timeout.
	_, err := client.Kasada.CD(ctx, &KasadaCDRequest{})
	if !IsErrorCode(err, "solver_busy") || errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
	if ctx.Err() != nil {
		t.Fatal("client waited for the context deadline")
	}
}

func TestSolverBusyRetryWaitHonorsCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":5000}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 1}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()

	started := time.Now()
	_, err := client.Kasada.CD(ctx, &KasadaCDRequest{})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("cancellation ignored for %s", elapsed)
	}
}

func TestSolverBusyRetryCanBeDisabled(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []Option
	}{
		{name: "zero budget", options: []Option{WithRetryPolicy(RetryPolicy{MaxRetries: 2}), WithSolverBusyRetryBudget(0)}},
		{name: "zero max retries", options: []Option{WithRetryPolicy(RetryPolicy{})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":1}`)
			}))
			defer server.Close()
			client := newTestClient(t, server, test.options...)
			_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
			if !IsErrorCode(err, "solver_busy") || calls.Load() != 1 {
				t.Fatalf("error/calls = %v/%d", err, calls.Load())
			}
		})
	}
}

func TestQuotaExceededIsNotRetriedLikeSolverBusy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"quota_exceeded","retry_after_ms":1}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 2}), WithSolverBusyRetryBudget(time.Minute))

	_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	if !IsErrorCode(err, "quota_exceeded") || calls.Load() != 1 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
}

func TestInternalErrorAfterSolverBusyIsRetriedOnce(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"solver_busy","retry_after_ms":1}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal_error"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithRetryPolicy(RetryPolicy{MaxRetries: 2}))

	_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
	if !IsErrorCode(err, "internal_error") || calls.Load() != 3 {
		t.Fatalf("error/calls = %v/%d", err, calls.Load())
	}
}

func TestRetryAfterMSParsing(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want time.Duration
	}{
		{name: "integer", body: `{"error":"solver_busy","retry_after_ms":1500}`, want: 1500 * time.Millisecond},
		{name: "fractional", body: `{"error":"solver_busy","retry_after_ms":2.5}`, want: 2500 * time.Microsecond},
		{name: "absent", body: `{"error":"solver_busy"}`},
		{name: "null", body: `{"error":"solver_busy","retry_after_ms":null}`},
		{name: "zero", body: `{"error":"solver_busy","retry_after_ms":0}`},
		{name: "negative", body: `{"error":"solver_busy","retry_after_ms":-5}`},
		{name: "string keeps the code", body: `{"error":"solver_busy","retry_after_ms":"1500"}`},
		{name: "object keeps the code", body: `{"error":"solver_busy","retry_after_ms":{}}`},
		{name: "overflowing number keeps the code", body: `{"error":"solver_busy","retry_after_ms":1e400}`},
		{name: "capped", body: `{"error":"solver_busy","retry_after_ms":1e12}`, want: maxRetryDelay},
		{name: "akamai envelope", body: `{"success":false,"error_code":"solver_busy","retry_after_ms":750}`, want: 750 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			apiErr := decodeAPIError([]byte(test.body))
			if apiErr.Code != "solver_busy" || apiErr.RetryAfter != test.want {
				t.Fatalf("code/retry after = %q/%s, want solver_busy/%s", apiErr.Code, apiErr.RetryAfter, test.want)
			}
		})
	}

	for _, test := range []struct {
		name string
		body string
		want time.Duration
	}{
		{name: "header only", body: `{"error":"solver_busy"}`, want: 2 * time.Second},
		{name: "body wins", body: `{"error":"solver_busy","retry_after_ms":300}`, want: 300 * time.Millisecond},
		{name: "invalid body falls back to header", body: `{"error":"solver_busy","retry_after_ms":"soon"}`, want: 2 * time.Second},
	} {
		t.Run("response "+test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := newTestClient(t, server)
			_, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != "solver_busy" || apiErr.RetryAfter != test.want {
				t.Fatalf("error = %#v, want retry after %s", apiErr, test.want)
			}
		})
	}
}

func newTestClient(t *testing.T, server *httptest.Server, options ...Option) *Client {
	t.Helper()
	options = append([]Option{WithBaseURL(server.URL), WithHTTPClient(server.Client()), WithRetryPolicy(RetryPolicy{})}, options...)
	client, err := NewClient("test-key", options...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// A PerimeterX proxy_error names how the customer's proxy failed and is not
// retried: the same exit fails again, the caller must switch exits.
func TestProxyErrorCarriesReasonAndIsNotRetried(t *testing.T) {
	apiErr := decodeAPIError([]byte(`{"error":"proxy_error","message":"your proxy rejected the credentials (407); check the user and password","stage":"prelude","reason":"proxy_auth_failed"}`))
	apiErr.Response.StatusCode = http.StatusFailedDependency
	if apiErr.Code != "proxy_error" || apiErr.Reason != "proxy_auth_failed" || apiErr.Stage != "prelude" {
		t.Fatalf("decoded %+v", apiErr)
	}
	if apiErr.Retryable() {
		t.Fatal("proxy_error must not be retried through the same exit")
	}
	other := decodeAPIError([]byte(`{"error":"target_error"}`))
	if other.Reason != "" {
		t.Fatalf("reason on another code = %q", other.Reason)
	}
	// target_error answers 424, not a 5xx, and stays retryable.
	other.Response.StatusCode = http.StatusFailedDependency
	if !other.Retryable() {
		t.Fatal("target_error at 424 is no longer retryable")
	}
}
