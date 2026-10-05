package bypassfast

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The edge gives every route 60 s but PerimeterX 150 s, so PerimeterX calls
// carry their own, longer per-attempt timeout, on the typed methods and on
// the generic Solve alike.
func TestPerimeterxRoutesUseTheirOwnTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, `{"success":true,"session":"session"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithTimeout(25*time.Millisecond), WithPerimeterxTimeout(5*time.Second))

	_, err := client.Balance(context.Background())
	var requestErr *RequestError
	if !errors.As(err, &requestErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("balance with a 25 ms timeout = %v, want a RequestError wrapping context.DeadlineExceeded", err)
	}

	result, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{
		URL: "https://www.example.com/", Proxy: "http://user:pass@proxy.example.net:8000",
	})
	if err != nil || !result.Success {
		t.Fatalf("perimeterx init = %#v, %v", result, err)
	}

	var out map[string]any
	if _, err := client.Solve(context.Background(), SolverPerimeterx, map[string]any{"mode": "init"}, &out); err != nil {
		t.Fatalf("generic perimeterx solve = %v", err)
	}
	if _, err := client.Solve(context.Background(), SolverKasada, map[string]any{"mode": "cd"}, &out); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("generic kasada solve with a 25 ms timeout = %v, want context.DeadlineExceeded", err)
	}
}

// A caller's context deadline still bounds the whole call when it is shorter
// than the per-attempt timeout.
func TestCallerDeadlineBeatsThePerAttemptTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithPerimeterxTimeout(5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var out map[string]any
	if _, err := client.Solve(ctx, SolverPerimeterx, map[string]any{"mode": "init"}, &out); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("solve under a 20 ms caller deadline = %v, want context.DeadlineExceeded", err)
	}
}

func TestSolveUsesThePerimeterxRequestLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	// Above the 1 MiB limit of every other route, below the 2 MiB PerimeterX
	// limit; gzip shrinks it on the wire.
	body := map[string]any{"mode": "holdcaptcha", "blocked": strings.Repeat("a", maxRequestBytes)}
	var out map[string]any
	if _, err := client.Solve(context.Background(), SolverPerimeterx, body, &out); err != nil {
		t.Fatalf("perimeterx solve above 1 MiB = %v", err)
	}
	var validationErr *ValidationError
	if _, err := client.Solve(context.Background(), SolverAkamai, body, &out); !errors.As(err, &validationErr) {
		t.Fatalf("akamai solve above 1 MiB = %v, want ValidationError", err)
	}
}

func TestTimeoutOptionsRejectInvalidValues(t *testing.T) {
	for _, option := range []Option{
		WithTimeout(0), WithTimeout(-time.Second), WithTimeout(2 * time.Hour),
		WithPerimeterxTimeout(0), WithPerimeterxTimeout(2 * time.Hour),
	} {
		if _, err := NewClient("test-key", option); err == nil {
			t.Fatal("NewClient accepted an invalid timeout")
		}
	}
}
