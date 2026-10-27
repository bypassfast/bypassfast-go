package bypassfast

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// recordingServer answers each request from the script: a 409
// script_cache_miss for every call whose index is in misses, otherwise the
// given 2xx body. Bodies are decoded for the caller.
func recordingServer(t *testing.T, misses map[int]bool, ok string) (*httptest.Server, func() []map[string]any) {
	t.Helper()
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
		if misses[call] {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"script_cache_miss"}`)
			return
		}
		_, _ = io.WriteString(w, ok)
	}))
	t.Cleanup(server.Close)
	return server, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), requests...)
	}
}

func hasScript(body map[string]any) bool {
	_, ok := body["script"]
	return ok
}

func TestKasadaSensorAndCDTravelHashFirst(t *testing.T) {
	server, requests := recordingServer(t, map[int]bool{1: true}, `{"payload":"p","headers":{"x-kpsdk-v":"j-1.0"},"script_id":"srv","client_hints":{"sec-ch-ua-platform":"\"Windows\""}}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	source := "raw p.js source"
	sensor, err := client.Kasada.Sensor(context.Background(), &KasadaSensorRequest{Script: source, UserAgent: "ua", Seed: 7})
	if err != nil || sensor.Response.Attempts != 2 || sensor.ScriptID != "srv" || sensor.ClientHints["sec-ch-ua-platform"] != `"Windows"` {
		t.Fatalf("sensor = %#v, %v", sensor, err)
	}
	// The sensor's resend registered the script: cd is compact at once.
	cd, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{Script: source, WorkTime: 250})
	if err != nil || cd.Response.Attempts != 1 || cd.ScriptID != "srv" {
		t.Fatalf("cd = %#v, %v", cd, err)
	}
	got := requests()
	if len(got) != 3 {
		t.Fatalf("requests = %d", len(got))
	}
	want := sha256Hex([]byte(source))
	for i, body := range got {
		if body["script_id"] != want {
			t.Fatalf("request %d script_id = %#v", i, body["script_id"])
		}
	}
	if hasScript(got[0]) || got[1]["script"] != source || hasScript(got[2]) {
		t.Fatalf("scripts sent = %v %v %v", hasScript(got[0]), hasScript(got[1]), hasScript(got[2]))
	}
	if got[0]["mode"] != "sensor" || got[2]["mode"] != "cd" || got[2]["work_time"] != float64(250) || got[0]["seed"] != float64(7) {
		t.Fatalf("modes/fields = %#v", got)
	}
}

func TestSBSDTravelsHashFirstAndRepeatsOnce(t *testing.T) {
	server, requests := recordingServer(t, map[int]bool{1: true}, `{"success":true,"body":"encrypted","session":"s1","script_id":"srv"}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	script := []byte("sbsd script")
	result, err := client.Akamai.SBSD(context.Background(), &AkamaiSBSDRequest{Script: script, SBSDO: "cookie", Session: "prior"})
	if err != nil || result.Response.Attempts != 2 || result.Body != "encrypted" {
		t.Fatalf("result = %#v, %v", result, err)
	}
	got := requests()
	if len(got) != 2 || hasScript(got[0]) || got[1]["script"] != base64.StdEncoding.EncodeToString(script) {
		t.Fatalf("requests = %#v", got)
	}
	for _, body := range got {
		if body["script_id"] != sha256Hex(script) || body["session"] != "prior" || body["sbsd_o"] != "cookie" {
			t.Fatalf("body = %#v", body)
		}
	}
}

// After one miss, the client sends the script body at once for the same
// script until a script-bearing call succeeds: a burst of solves for a new
// script costs one extra round trip, not one per call.
func TestRecentMissSendsTheScriptDirectly(t *testing.T) {
	server, requests := recordingServer(t, map[int]bool{1: true, 2: true}, `{"success":true,"sensor_data":"sensor"}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	now := time.Unix(1_790_000_000, 0)
	client.scripts.now = func() time.Time { return now }
	script := []byte("brand new script")
	request := &AkamaiSensorRequest{Script: script, ScriptURL: "https://example.com/a.js"}

	// Call 1: hash-first (miss), resend also fails: the miss stays remembered.
	if _, err := client.Akamai.Sensor(context.Background(), request); !IsErrorCode(err, "script_cache_miss") {
		t.Fatalf("err = %v", err)
	}
	// Call 2: inside the window, the script travels directly and registers.
	second, err := client.Akamai.Sensor(context.Background(), request)
	if err != nil || second.Response.Attempts != 1 {
		t.Fatalf("second = %#v, %v", second, err)
	}
	// Call 3: registered, so hash-first again.
	if _, err := client.Akamai.Sensor(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	got := requests()
	if len(got) != 4 || hasScript(got[0]) || !hasScript(got[1]) || !hasScript(got[2]) || hasScript(got[3]) {
		t.Fatalf("script sent per request = %v %v %v %v", hasScript(got[0]), hasScript(got[1]), hasScript(got[2]), hasScript(got[3]))
	}
	// An old miss is forgotten.
	client.scripts.markMissed("akamai:" + sha256Hex(script))
	now = now.Add(scriptMissMemory)
	if _, err := client.Akamai.Sensor(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := requests(); hasScript(got[len(got)-1]) {
		t.Fatal("expired miss still sent the script directly")
	}
}

func TestScriptMemoryBoundsAndExpiry(t *testing.T) {
	memory := newScriptMemory(2)
	now := time.Unix(1_790_000_000, 0)
	memory.now = func() time.Time { return now }
	memory.markMissed("a")
	memory.markMissed("b")
	memory.markMissed("c") // evicts a
	if memory.recentlyMissed("a") || !memory.recentlyMissed("b") || !memory.recentlyMissed("c") || memory.len() != 2 {
		t.Fatalf("eviction: a=%v b=%v c=%v len=%d", memory.recentlyMissed("a"), memory.recentlyMissed("b"), memory.recentlyMissed("c"), memory.len())
	}
	memory.markRegistered("b")
	if memory.recentlyMissed("b") || memory.len() != 1 {
		t.Fatal("registered script still remembered as missing")
	}
	now = now.Add(scriptMissMemory)
	if memory.recentlyMissed("c") || memory.len() != 0 {
		t.Fatal("expired miss not forgotten")
	}
	memory.markMissed("")
	if memory.recentlyMissed("") || memory.len() != 0 {
		t.Fatal("empty key remembered")
	}
}

func TestExplicitScriptIDWithoutScriptReturnsTheMiss(t *testing.T) {
	server, requests := recordingServer(t, map[int]bool{1: true}, `{}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	id := ScriptID([]byte("script"))
	_, err := client.Kasada.Sensor(context.Background(), &KasadaSensorRequest{ScriptID: id, UserAgent: "ua"})
	if !IsErrorCode(err, "script_cache_miss") || len(requests()) != 1 {
		t.Fatalf("err = %v, requests = %d", err, len(requests()))
	}
	if _, err := client.Incapsula.Reese84(context.Background(), &IncapsulaReese84Request{Script: "s", ScriptID: "nothex"}); err == nil {
		t.Fatal("malformed script_id accepted")
	}
	if _, err := client.Kasada.CD(context.Background(), &KasadaCDRequest{Script: "s", ScriptID: ScriptID([]byte("other"))}); err == nil {
		t.Fatal("mismatched script_id accepted")
	}
	if _, err := client.Akamai.SBSD(context.Background(), &AkamaiSBSDRequest{ScriptID: " "}); err == nil {
		t.Fatal("SBSD without a script or script_id accepted")
	}
}

func TestAkamaiTelemetryIsRequestedAndReturned(t *testing.T) {
	server, requests := recordingServer(t, nil, `{"success":true,"sensor_data":"sensor","telemetry":"a=&&&e=bm&&&sensor_data=c2Vuc29y"}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	plain, err := client.Akamai.Sensor(context.Background(), &AkamaiSensorRequest{Session: "s"})
	if err != nil || plain.Telemetry != "a=&&&e=bm&&&sensor_data=c2Vuc29y" {
		t.Fatalf("plain = %#v, %v", plain, err)
	}
	if _, err := client.Akamai.Sensor(context.Background(), &AkamaiSensorRequest{Session: "s", Telemetry: true}); err != nil {
		t.Fatal(err)
	}
	got := requests()
	if _, sent := got[0]["telemetry"]; sent || got[1]["telemetry"] != true {
		t.Fatalf("telemetry flags = %#v / %#v", got[0]["telemetry"], got[1]["telemetry"])
	}
}

func TestPerimeterxClientHintsAreDecoded(t *testing.T) {
	server, _ := recordingServer(t, nil, `{"success":true,"cookies":[],"session":"s","ua":"ua","client_hints":{"sec-ch-ua":"\"Chromium\";v=\"155\"","sec-ch-ua-mobile":"?0","sec-ch-ua-platform":"\"macOS\""}}`)
	client := newTestClient(t, server, WithCompressionThreshold(-1))
	result, err := client.Perimeterx.Init(context.Background(), &PerimeterxInitRequest{URL: "https://example.com", Proxy: "http://u:p@proxy:1"})
	if err != nil || len(result.ClientHints) != 3 || result.ClientHints["sec-ch-ua-platform"] != `"macOS"` {
		t.Fatalf("result = %#v, %v", result, err)
	}
}
