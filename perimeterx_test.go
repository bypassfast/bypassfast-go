package bypassfast

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPerimeterxInitAndHoldWire(t *testing.T) {
	var mu sync.Mutex
	var requests []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/solve/perimeterx" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		requests = append(requests, body)
		mu.Unlock()
		switch body["mode"] {
		case "init":
			_, _ = io.WriteString(w, `{"success":true,"cookies":[{"name":"_pxvid","value":"v","domain":".example.com","path":"/"}],"session":"sess-1","cost":0.004}`)
		case "holdcaptcha":
			_, _ = io.WriteString(w, `{"success":false,"cookies":[],"session":"sess-2","cost":0.004}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))

	initResult, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{
		URL:       "https://www.example.com/en/booking",
		Proxy:     "socks5h://user:pass@host:1080",
		UserAgent: "Mozilla/5.0 Chrome/153.0.0.0",
		Platform:  PerimeterxPlatformChromeMac,
		Cookies:   []PerimeterxCookie{{Name: "ak_bmsc", Value: "x", Domain: ".example.com", Path: "/"}},
		Headers:   map[string]string{"x-custom": "value"},
	})
	if err != nil || initResult.Session != "sess-1" || initResult.Cost != 0.004 || len(initResult.Cookies) != 1 || initResult.Response.Attempts != 1 {
		t.Fatalf("init = %#v, %v", initResult, err)
	}
	if initResult.Rejected() {
		t.Fatal("init reported a rejection")
	}

	holdResult, err := client.Perimeterx.SolveHold(context.Background(), &PerimeterxHoldRequest{
		Session: initResult.Session,
		Proxy:   "socks5h://user:pass@host:1080",
		Blocked: &PerimeterxBlockedResponse{
			URL:        "https://www.example.com/api/v1/availability",
			Method:     "POST",
			Status:     428,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       "eyJhcHBJZCI6IlBYYWJjIn0=",
			BodyBase64: true,
		},
		Cookies: []PerimeterxCookie{{Name: "_abck", Value: "a", Domain: ".example.com", Path: "/"}, {Name: "_pxhd", Value: "h"}},
	})
	if err != nil || holdResult.Success || !holdResult.Rejected() || holdResult.ChangeExit() || holdResult.Retry != nil {
		t.Fatalf("hold = %#v, %v", holdResult, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("requests = %d", len(requests))
	}
	initWire := requests[0]
	if initWire["mode"] != "init" || initWire["url"] != "https://www.example.com/en/booking" || initWire["ua"] != "Mozilla/5.0 Chrome/153.0.0.0" || initWire["platform"] != "chrome-mac" {
		t.Fatalf("init wire = %#v", initWire)
	}
	if _, present := initWire["session"]; present {
		t.Fatalf("init wire carried a session: %#v", initWire)
	}
	if cookies, ok := initWire["cookies"].([]any); !ok || len(cookies) != 1 {
		t.Fatalf("init wire cookies = %#v", initWire["cookies"])
	}
	holdWire := requests[1]
	blocked, ok := holdWire["blocked"].(map[string]any)
	if holdWire["mode"] != "holdcaptcha" || holdWire["session"] != "sess-1" || !ok {
		t.Fatalf("hold wire = %#v", holdWire)
	}
	if blocked["status"] != float64(428) || blocked["method"] != "POST" || blocked["body_encoding"] != "base64" || blocked["body"] != "eyJhcHBJZCI6IlBYYWJjIn0=" {
		t.Fatalf("hold wire blocked = %#v", blocked)
	}
	if _, present := holdWire["ua"]; present {
		t.Fatalf("hold wire carried an empty ua: %#v", holdWire)
	}
	// The cookies held at the block travel with the hold, HUMAN's included.
	holdCookies, ok := holdWire["cookies"].([]any)
	if !ok || len(holdCookies) != 2 {
		t.Fatalf("hold wire cookies = %#v", holdWire["cookies"])
	}
	if first, _ := holdCookies[0].(map[string]any); first["name"] != "_abck" || first["domain"] != ".example.com" {
		t.Fatalf("hold wire cookies[0] = %#v", holdCookies[0])
	}
	if second, _ := holdCookies[1].(map[string]any); second["name"] != "_pxhd" {
		t.Fatalf("hold wire cookies[1] = %#v", holdCookies[1])
	}
}

// A hold without cookies is sent without a cookies key: the solver then
// keeps its own jar and refreshes the page before the hold.
func TestPerimeterxHoldWithoutCookiesOmitsTheKey(t *testing.T) {
	var wire map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&wire)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"cookies":[],"session":"sess-2","cost":0.004}`))
	}))
	defer server.Close()
	client, err := NewClient("bf_test_key", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Perimeterx.SolveHold(context.Background(), &PerimeterxHoldRequest{
		Session: "s", Proxy: "http://u:p@h:1", Blocked: &PerimeterxBlockedResponse{URL: "https://www.example.com/api", Status: 428, Body: "{}"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["cookies"]; present {
		t.Fatalf("hold wire carried an empty cookies key: %#v", wire)
	}
}

// An init without a user agent is sent without a ua key; the solver draws
// the Chrome build and the SDK hands its ua back to the caller.
func TestPerimeterxInitWithoutUserAgentAdoptsTheSolverDraw(t *testing.T) {
	var wire map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = io.WriteString(w, `{"success":true,"cookies":[],"session":"sess-3","ua":"Mozilla/5.0 Chrome/152.0.0.0","cost":0.004}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	result, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{URL: "https://www.example.com/", Proxy: "socks5h://user:pass@host:1080"})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := wire["ua"]; present {
		t.Fatalf("init wire carried an empty ua: %#v", wire)
	}
	if result.UserAgent != "Mozilla/5.0 Chrome/152.0.0.0" || result.Session != "sess-3" {
		t.Fatalf("init = %#v", result)
	}
}

// An init without Accept-Language is sent without the key and returns the
// value the solver drew; one with it keeps the caller's own even when the
// API does not echo it.
func TestPerimeterxInitAdoptsTheSessionAcceptLanguage(t *testing.T) {
	var wires []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Errorf("decode request: %v", err)
		}
		wires = append(wires, wire)
		if _, sent := wire["accept_language"]; sent {
			_, _ = io.WriteString(w, `{"success":true,"cookies":[],"session":"s","cost":0.004}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"cookies":[],"session":"s","accept_language":"en-GB,en;q=0.9","cost":0.004}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	drawn, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{URL: "https://www.example.com/", Proxy: "socks5h://user:pass@host:1080"})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := wires[0]["accept_language"]; present || drawn.AcceptLanguage != "en-GB,en;q=0.9" {
		t.Fatalf("drawn init: wire %#v, result %q", wires[0], drawn.AcceptLanguage)
	}
	own, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{URL: "https://www.example.com/", Proxy: "socks5h://user:pass@host:1080", AcceptLanguage: "tr-TR,tr;q=0.9"})
	if err != nil {
		t.Fatal(err)
	}
	if wires[1]["accept_language"] != "tr-TR,tr;q=0.9" || own.AcceptLanguage != "tr-TR,tr;q=0.9" {
		t.Fatalf("own init: wire %#v, result %q", wires[1], own.AcceptLanguage)
	}
}

func TestPerimeterxValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached the server")
	}))
	defer server.Close()
	client := newTestClient(t, server)

	cases := []struct {
		name string
		call func() error
	}{
		{"nil init", func() error { _, err := client.Perimeterx.Init(context.Background(), nil); return err }},
		{"init without url", func() error {
			_, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{Proxy: "p", UserAgent: "u"})
			return err
		}},
		{"init without proxy", func() error {
			_, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{URL: "https://e", UserAgent: "u"})
			return err
		}},
		{"nil hold", func() error { _, err := client.Perimeterx.SolveHold(context.Background(), nil); return err }},
		{"hold without session", func() error {
			_, err := client.Perimeterx.SolveHold(context.Background(), &PerimeterxHoldRequest{Proxy: "p", Blocked: &PerimeterxBlockedResponse{URL: "https://e"}})
			return err
		}},
		{"hold without blocked", func() error {
			_, err := client.Perimeterx.SolveHold(context.Background(), &PerimeterxHoldRequest{Session: "s", Proxy: "p"})
			return err
		}},
		{"hold without any url", func() error {
			_, err := client.Perimeterx.SolveHold(context.Background(), &PerimeterxHoldRequest{Session: "s", Proxy: "p", Blocked: &PerimeterxBlockedResponse{Status: 428}})
			return err
		}},
	}
	for _, tc := range cases {
		var validationErr *ValidationError
		if err := tc.call(); !errors.As(err, &validationErr) {
			t.Fatalf("%s: error = %T %v", tc.name, err, err)
		}
	}
}

func TestPerimeterxAllowsTwoMiBBlockPages(t *testing.T) {
	var received int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = len(body)
		_, _ = io.WriteString(w, `{"success":true,"cookies":[],"session":"s","cost":0.004}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))

	// Bracket-free filler: encoding/json escapes HTML angle brackets, which
	// would inflate the encoded size well past the block page itself.
	page := strings.Repeat("px-captcha ", (maxRequestBytes+512*1024)/len("px-captcha "))
	hold := &PerimeterxHoldRequest{Session: "s", Proxy: "p", Blocked: &PerimeterxBlockedResponse{URL: "https://e", Status: 403, Body: page}}
	result, err := client.Perimeterx.SolveHold(context.Background(), hold)
	if err != nil || !result.Success || received <= maxRequestBytes {
		t.Fatalf("result/err/received = %#v/%v/%d", result, err, received)
	}

	hold.Blocked.Body = strings.Repeat("x", maxPerimeterxRequestBytes+1)
	var validationErr *ValidationError
	if _, err := client.Perimeterx.SolveHold(context.Background(), hold); !errors.As(err, &validationErr) {
		t.Fatalf("oversized error = %T %v", err, err)
	}
}

func TestPerimeterxGenericSolveAcceptsSolver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/solve/perimeterx" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	var response struct {
		Success bool `json:"success"`
	}
	if _, err := client.Solve(context.Background(), SolverPerimeterx, map[string]any{"mode": "init"}, &response); err != nil || !response.Success {
		t.Fatalf("response/err = %#v/%v", response, err)
	}
}
