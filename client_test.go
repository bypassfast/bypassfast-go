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

			_, err := client.DataDome.Solve(context.Background(), &DataDomeRequest{Target: "https://example.com"})
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

	_, err := client.DataDome.Solve(context.Background(), &DataDomeRequest{Target: "https://example.com"})
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
	_, err = client.DataDome.Solve(context.Background(), &DataDomeRequest{Target: "https://example.com"})
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

	_, err := client.DataDome.Solve(context.Background(), &DataDomeRequest{Target: "https://example.com"})
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
