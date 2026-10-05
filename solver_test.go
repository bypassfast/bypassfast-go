package bypassfast

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAkamaiSensorScriptReuseAndFallback(t *testing.T) {
	var mu sync.Mutex
	var requests []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		requests = append(requests, body)
		call := len(requests)
		mu.Unlock()
		if call == 2 {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error_code":"script_cache_miss"}`)
			return
		}
		_, _ = io.WriteString(w, `{"cost":0.002,"success":true,"sensor_data":"sensor","ua":"ua","session":"session","script_id":"server-id"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	script := []byte("raw <sensor> javascript")
	request := &AkamaiSensorRequest{URL: "https://example.com", Script: script, ScriptURL: "https://example.com/a.js"}

	first, err := client.Akamai.Sensor(context.Background(), request)
	if err != nil || first.SensorData != "sensor" {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := client.Akamai.Sensor(context.Background(), request)
	if err != nil || second.Response.Attempts != 2 {
		t.Fatalf("second = %#v, %v", second, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("requests = %d", len(requests))
	}
	for _, request := range requests {
		if _, exists := request["config"]; exists {
			t.Fatal("sensor request included config")
		}
	}
	wantScript := base64.StdEncoding.EncodeToString(script)
	if requests[0]["script"] != wantScript || requests[0]["script_id"] != sha256Hex(script) {
		t.Fatalf("first request = %#v", requests[0])
	}
	if _, exists := requests[1]["script"]; exists || requests[1]["script_id"] != sha256Hex(script) {
		t.Fatalf("compact request = %#v", requests[1])
	}
	if requests[2]["script"] != wantScript {
		t.Fatalf("fallback request = %#v", requests[2])
	}
}

func TestAkamaiRejectsMismatchedScriptIDLocally(t *testing.T) {
	client, err := NewClient("test-key")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Akamai.Sensor(context.Background(), &AkamaiSensorRequest{
		Script:   []byte("script"),
		ScriptID: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("mismatched script ID accepted")
	}
}

func TestAkamaiExplicitScriptIDUsesRemoteCacheFirst(t *testing.T) {
	script := []byte("raw script available for fallback")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["script_id"] != AkamaiScriptID(script) {
			t.Errorf("script_id = %#v", body["script_id"])
		}
		if call == 1 {
			if _, exists := body["script"]; exists {
				t.Errorf("first request uploaded script: %#v", body)
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error_code":"script_cache_miss"}`)
			return
		}
		if body["script"] != base64.StdEncoding.EncodeToString(script) {
			t.Errorf("fallback script = %#v", body["script"])
		}
		_, _ = io.WriteString(w, `{"success":true,"sensor_data":"sensor"}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))

	result, err := client.Akamai.Sensor(context.Background(), &AkamaiSensorRequest{
		Script:   script,
		ScriptID: AkamaiScriptID(script),
	})
	if err != nil || result.Response.Attempts != 2 || calls.Load() != 2 {
		t.Fatalf("result/error/calls = %#v/%v/%d", result, err, calls.Load())
	}
}

func TestIncapsulaScriptReuseAndFallback(t *testing.T) {
	var mu sync.Mutex
	var scripts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Mode                       string     `json:"mode"`
			Script                     string     `json:"script"`
			DocumentHTML               string     `json:"document_html"`
			DocumentScriptSourceGroups [][]string `json:"document_script_source_groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		scripts = append(scripts, body.Script)
		call := len(scripts)
		mu.Unlock()
		if body.Mode != "reese84" {
			t.Errorf("mode = %q", body.Mode)
		}
		if body.DocumentHTML == "" || len(body.DocumentScriptSourceGroups) != 1 || len(body.DocumentScriptSourceGroups[0]) != 1 {
			t.Errorf("document context was not preserved")
		}
		if call == 2 {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"script_cache_miss"}`)
			return
		}
		_, _ = io.WriteString(w, `{"payload":"payload","backend":"replay","duration_ms":2}`)
	}))
	defer server.Close()
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	request := &IncapsulaReese84Request{
		Script: "raw script", ScriptURL: "https://example.com/loader", URL: "https://example.com", UserAgent: "ua",
		DocumentHTML:               `<script async src="/static/build"></script>`,
		DocumentScriptSourceGroups: [][]string{{"https://example.com/static/build"}},
	}
	if _, err := client.Incapsula.Reese84(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := client.Incapsula.Reese84(context.Background(), request)
	if err != nil || result.Response.Attempts != 2 {
		t.Fatalf("result/error = %#v/%v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(scripts) != 3 || scripts[0] != "raw script" || scripts[1] != "" || scripts[2] != "raw script" {
		t.Fatalf("scripts = %#v", scripts)
	}
}

func TestTypedModesSendCanonicalContracts(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantMode   string
		response   string
		invoke     func(context.Context, *Client) error
		assertBody func(*testing.T, map[string]any)
	}{
		{
			name:     "akamai sbsd",
			path:     "/v1/solve/akamai",
			wantMode: "sbsd",
			response: `{"success":true,"body":"encrypted"}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Akamai.SBSD(ctx, &AkamaiSBSDRequest{Script: []byte("sbsd"), SBSDO: "cookie"})
				return err
			},
			assertBody: func(t *testing.T, body map[string]any) {
				if body["script"] != base64.StdEncoding.EncodeToString([]byte("sbsd")) || body["sbsd_o"] != "cookie" {
					t.Fatalf("body = %#v", body)
				}
			},
		},
		{
			name:     "akamai cpt",
			path:     "/v1/solve/akamai",
			wantMode: "cpt",
			response: `{"success":true,"answers":["a"]}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Akamai.CPT(ctx, &AkamaiCPTRequest{Token: "token", Difficulty: 16})
				return err
			},
		},
		{
			name:     "akamai sec_cpt",
			path:     "/v1/solve/akamai",
			wantMode: "sec_cpt",
			response: `{"success":true,"answers":["0.8"],"body":"{}"}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Akamai.SecCPT(ctx, &AkamaiSecCPTRequest{
					Token: "token", SecCPT: "prefix~1~rest", Timestamp: 1783387618,
					Nonce: "nonce", Difficulty: 10000, Count: 1,
				})
				return err
			},
			assertBody: func(t *testing.T, body map[string]any) {
				if body["sec_cpt"] != "prefix~1~rest" || body["timestamp"] != float64(1783387618) ||
					body["nonce"] != "nonce" || body["difficulty"] != float64(10000) || body["count"] != float64(1) {
					t.Fatalf("body = %#v", body)
				}
			},
		},
		{
			name:     "kasada sensor",
			path:     "/v1/solve/kasada",
			wantMode: "sensor",
			response: `{"payload":"p"}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Kasada.Sensor(ctx, &KasadaSensorRequest{Script: "p.js", UserAgent: "ua", PageOrigin: "https://example.com"})
				return err
			},
			assertBody: func(t *testing.T, body map[string]any) {
				if body["page_origin"] != "https://example.com" {
					t.Fatalf("body = %#v", body)
				}
			},
		},
		{
			name:     "kasada cd",
			path:     "/v1/solve/kasada",
			wantMode: "cd",
			response: `{"payload":"cd"}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Kasada.CD(ctx, &KasadaCDRequest{WorkTime: 250, SubchallengeCount: 2})
				return err
			},
			assertBody: func(t *testing.T, body map[string]any) {
				if body["work_time"] != float64(250) || body["subchallenge_count"] != float64(2) {
					t.Fatalf("body = %#v", body)
				}
			},
		},
		{
			name:     "incapsula utmvc",
			path:     "/v1/solve/incapsula",
			wantMode: "utmvc",
			response: `{"payload":"cookie","cookie":"cookie"}`,
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.Incapsula.UTMVC(ctx, &IncapsulaUTMVCRequest{SessionIDs: []string{"s1"}})
				return err
			},
			assertBody: func(t *testing.T, body map[string]any) {
				ids, ok := body["session_ids"].([]any)
				if !ok || len(ids) != 1 || ids[0] != "s1" {
					t.Fatalf("body = %#v", body)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Errorf("path = %q", r.URL.Path)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode: %v", err)
				}
				if test.wantMode == "" {
					if _, exists := body["mode"]; exists {
						t.Errorf("unexpected mode in %#v", body)
					}
				} else if body["mode"] != test.wantMode {
					t.Errorf("mode = %#v", body["mode"])
				}
				if test.assertBody != nil {
					test.assertBody(t, body)
				}
				_, _ = io.WriteString(w, test.response)
			}))
			defer server.Close()
			client := newTestClient(t, server, WithCompressionThreshold(-1))
			if err := test.invoke(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}
