package bypassfast

import (
	"context"
	"encoding/base64"
)

// AkamaiService provides Akamai Bot Manager solve modes.
type AkamaiService struct {
	client *Client
}

// AkamaiSensorRequest generates Bot Manager sensor_data. Script contains raw
// JavaScript bytes; the SDK performs the required base64 encoding, sends only
// the script's SHA-256 as script_id, and uploads the bytes once, only when the
// API has never seen that script. ScriptID may be set instead of Script when
// the bytes are not at hand; a cache miss is then returned as an APIError.
//
// Set Pace on the calls after the first to have each response held until a
// person's interval (2.5-4 s) has passed since the previous sensor: a page
// posts seconds apart, and sites score sessions whose sensors arrive a
// fraction of a second apart. A client that spaces its own calls does not
// need it.
//
// Set Telemetry when the site protects its API calls with an
// Akamai-BM-Telemetry request header instead of a sensor post: the response
// then carries the ready-to-send header value in Telemetry.
type AkamaiSensorRequest struct {
	URL            string
	UserAgent      string
	ABCK           string
	BMSZ           string
	Script         []byte
	ScriptID       string
	ScriptURL      string
	AcceptLanguage string
	Language       string
	Timezone       string
	Session        string
	Pace           bool
	Telemetry      bool
}

// AkamaiSensorResponse contains the artifact and exact client identity that
// must be used for the target exchange. ClientHints are the UA client hints
// of the device behind the sensor: send sec-ch-ua, sec-ch-ua-mobile and
// sec-ch-ua-platform on every request, and the others only to sites whose
// Accept-CH header asks for them. Telemetry is the Akamai-BM-Telemetry header
// value, present when the request asked for it.
type AkamaiSensorResponse struct {
	Cost        float64           `json:"cost"`
	Success     bool              `json:"success"`
	SensorData  string            `json:"sensor_data"`
	UserAgent   string            `json:"ua"`
	Session     string            `json:"session"`
	Language    string            `json:"language"`
	ScriptID    string            `json:"script_id"`
	ClientHints map[string]string `json:"client_hints,omitempty"`
	Telemetry   string            `json:"telemetry,omitempty"`
	// PacedMS is how long the API held a paced response before answering.
	PacedMS  int          `json:"paced_ms,omitempty"`
	Response ResponseMeta `json:"-"`
}

type akamaiSensorWire struct {
	Mode           string `json:"mode"`
	URL            string `json:"url"`
	UserAgent      string `json:"ua"`
	ABCK           string `json:"abck"`
	BMSZ           string `json:"bm_sz"`
	Script         string `json:"script,omitempty"`
	ScriptID       string `json:"script_id,omitempty"`
	ScriptURL      string `json:"script_url"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	Language       string `json:"language,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	Session        string `json:"session,omitempty"`
	Pace           bool   `json:"pace,omitempty"`
	Telemetry      bool   `json:"telemetry,omitempty"`
}

// Sensor generates Akamai Bot Manager sensor_data. A fresh session sends the
// script as its script_id and uploads the bytes once on a cache miss; a call
// that continues a Session sends neither, since the session holds the script
// state.
func (s *AkamaiService) Sensor(ctx context.Context, request *AkamaiSensorRequest) (*AkamaiSensorResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := akamaiSensorWire{
		Mode:           "sensor",
		URL:            request.URL,
		UserAgent:      request.UserAgent,
		ABCK:           request.ABCK,
		BMSZ:           request.BMSZ,
		ScriptURL:      request.ScriptURL,
		AcceptLanguage: request.AcceptLanguage,
		Language:       request.Language,
		Timezone:       request.Timezone,
		Session:        request.Session,
		Pace:           request.Pace,
		Telemetry:      request.Telemetry,
	}
	var scriptID string
	var script []byte
	if request.Session == "" {
		var err error
		if scriptID, err = resolveScriptID(request.ScriptID, request.Script); err != nil {
			return nil, err
		}
		script = request.Script
		wire.ScriptID = scriptID
	}
	result := new(AkamaiSensorResponse)
	meta, err := s.client.solveScript(ctx, scriptExchange{
		path:        "/v1/solve/akamai",
		key:         "akamai:" + scriptID,
		hasScript:   len(script) > 0,
		scriptBytes: base64Len(len(script)),
		build: func(withScript bool) any {
			out := wire
			if withScript {
				out.Script = base64.StdEncoding.EncodeToString(script)
			}
			return out
		},
		limit:   maxRequestBytes,
		timeout: s.client.timeout,
	}, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	if result.ScriptID == "" {
		result.ScriptID = scriptID
	}
	return result, nil
}

// AkamaiSBSDRequest generates the encrypted Akamai side-band payload. Script
// contains raw JavaScript bytes: the SDK base64-encodes it, sends only its
// SHA-256 as script_id and uploads the bytes once on a cache miss. Later
// calls may set ScriptID (also returned) instead of Script.
//
// A page posts SBSD several times and every post must describe the same
// machine: keep the Session the first response returned and set it on every
// later SBSD (or sensor) call for that page.
//
// Post "telemetry" asks for the page's next telemetry post instead of the
// fingerprint (the program sends two after it, built from the input the
// sensor recorded on the same Session). Wait WaitMS before posting the body,
// or set Pace to have the response held until then.
type AkamaiSBSDRequest struct {
	URL             string
	UserAgent       string
	Script          []byte
	ScriptID        string
	Session         string
	Post            string
	Pace            bool
	ScriptURL       string
	SBSDO           string
	AcceptLanguage  string
	Language        string
	Timezone        string
	UUID            string
	ResourceURLs    []string
	DOMResourceURLs []string
}

// AkamaiSBSDResponse contains the complete encrypted body to submit upstream,
// the Session that pins this page's device for later calls, the ScriptID
// those calls may send instead of the script, and the device's ClientHints.
type AkamaiSBSDResponse struct {
	Cost        float64           `json:"cost"`
	Success     bool              `json:"success"`
	Body        string            `json:"body"`
	Session     string            `json:"session"`
	ScriptID    string            `json:"script_id"`
	ClientHints map[string]string `json:"client_hints,omitempty"`
	// Post is "telemetry" on a telemetry response; Ind is which of the two
	// posts it is and WaitMS how long to wait before posting the body.
	Post     string       `json:"sbsd_post,omitempty"`
	Ind      int          `json:"ind,omitempty"`
	WaitMS   int          `json:"wait_ms,omitempty"`
	Response ResponseMeta `json:"-"`
}

type akamaiSBSDWire struct {
	Mode            string   `json:"mode"`
	URL             string   `json:"url"`
	UserAgent       string   `json:"ua"`
	Script          string   `json:"script,omitempty"`
	ScriptID        string   `json:"script_id,omitempty"`
	Session         string   `json:"session,omitempty"`
	Post            string   `json:"sbsd_post,omitempty"`
	Pace            bool     `json:"pace,omitempty"`
	ScriptURL       string   `json:"script_url"`
	SBSDO           string   `json:"sbsd_o"`
	AcceptLanguage  string   `json:"accept_language,omitempty"`
	Language        string   `json:"language,omitempty"`
	Timezone        string   `json:"timezone,omitempty"`
	UUID            string   `json:"uuid,omitempty"`
	ResourceURLs    []string `json:"resource_urls,omitempty"`
	DOMResourceURLs []string `json:"dom_resource_urls,omitempty"`
}

// SBSD generates an encrypted side-band payload.
func (s *AkamaiService) SBSD(ctx context.Context, request *AkamaiSBSDRequest) (*AkamaiSBSDResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	scriptID, err := resolveScriptID(request.ScriptID, request.Script)
	if err != nil {
		return nil, err
	}
	if scriptID == "" {
		return nil, &ValidationError{Field: "script", Message: "set Script, or ScriptID from an earlier response"}
	}
	wire := akamaiSBSDWire{
		Mode:            "sbsd",
		URL:             request.URL,
		UserAgent:       request.UserAgent,
		ScriptID:        scriptID,
		Session:         request.Session,
		Post:            request.Post,
		Pace:            request.Pace,
		ScriptURL:       request.ScriptURL,
		SBSDO:           request.SBSDO,
		AcceptLanguage:  request.AcceptLanguage,
		Language:        request.Language,
		Timezone:        request.Timezone,
		UUID:            request.UUID,
		ResourceURLs:    request.ResourceURLs,
		DOMResourceURLs: request.DOMResourceURLs,
	}
	script := request.Script
	result := new(AkamaiSBSDResponse)
	meta, err := s.client.solveScript(ctx, scriptExchange{
		path:        "/v1/solve/akamai",
		key:         "akamai:" + scriptID,
		hasScript:   len(script) > 0,
		scriptBytes: base64Len(len(script)),
		build: func(withScript bool) any {
			out := wire
			if withScript {
				out.Script = base64.StdEncoding.EncodeToString(script)
			}
			return out
		},
		limit:   maxRequestBytes,
		timeout: s.client.timeout,
	}, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	if result.ScriptID == "" {
		result.ScriptID = scriptID
	}
	return result, nil
}

// AkamaiCPTRequest solves the pure-compute Sec-CPT challenge.
type AkamaiCPTRequest struct {
	Token      string
	Difficulty int
}

// AkamaiCPTResponse contains the ten Sec-CPT proof answers.
type AkamaiCPTResponse struct {
	Cost     float64      `json:"cost"`
	Success  bool         `json:"success"`
	Answers  []string     `json:"answers"`
	Response ResponseMeta `json:"-"`
}

// CPT solves an Akamai Sec-CPT proof-of-work challenge.
func (s *AkamaiService) CPT(ctx context.Context, request *AkamaiCPTRequest) (*AkamaiCPTResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := struct {
		Mode       string `json:"mode"`
		Token      string `json:"token"`
		Difficulty int    `json:"difficulty"`
	}{Mode: "cpt", Token: request.Token, Difficulty: request.Difficulty}
	result := new(AkamaiCPTResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}

// AkamaiSecCPTRequest answers the sec-cpt "Challenge Validation" page (the
// iframe with provider="crypto"). Token, Timestamp, Nonce, Difficulty and
// Count come from the base64 JSON in the iframe's challenge attribute or from
// a chained /_sec/verify response; keep the previous Count when a chained
// response omits it. SecCPT is the sec_cpt cookie value.
type AkamaiSecCPTRequest struct {
	Token      string
	SecCPT     string
	Timestamp  int64
	Nonce      string
	Difficulty int
	Count      int
}

// AkamaiSecCPTResponse carries Count proof answers and Body, the exact
// request body to POST to /_sec/verify?provider=<provider>.
type AkamaiSecCPTResponse struct {
	Cost     float64      `json:"cost"`
	Success  bool         `json:"success"`
	Answers  []string     `json:"answers"`
	Body     string       `json:"body"`
	Response ResponseMeta `json:"-"`
}

// SecCPT solves the proof of work of an Akamai sec-cpt challenge page.
func (s *AkamaiService) SecCPT(ctx context.Context, request *AkamaiSecCPTRequest) (*AkamaiSecCPTResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := struct {
		Mode       string `json:"mode"`
		Token      string `json:"token"`
		SecCPT     string `json:"sec_cpt"`
		Timestamp  int64  `json:"timestamp"`
		Nonce      string `json:"nonce"`
		Difficulty int    `json:"difficulty"`
		Count      int    `json:"count"`
	}{
		Mode: "sec_cpt", Token: request.Token, SecCPT: request.SecCPT, Timestamp: request.Timestamp,
		Nonce: request.Nonce, Difficulty: request.Difficulty, Count: request.Count,
	}
	result := new(AkamaiSecCPTResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}

// AkamaiScriptID returns the script_id for raw Akamai JavaScript bytes. It is
// ScriptID under its original name.
func AkamaiScriptID(rawScript []byte) string {
	return ScriptID(rawScript)
}
