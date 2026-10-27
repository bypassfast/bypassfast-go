package bypassfast

import "context"

// KasadaService provides Kasada sensor and proof-of-work modes.
type KasadaService struct {
	client *Client
}

// KasadaSensorRequest generates a full Kasada payload. Script is the raw p.js
// source; unlike Akamai, it must not be base64-encoded. The SDK sends only
// its SHA-256 as script_id and uploads the source once, only when the API has
// never seen that script. ScriptID may be set instead of Script when the
// source is not at hand; a cache miss is then returned as an APIError.
type KasadaSensorRequest struct {
	Script             string            `json:"script"`
	ScriptID           string            `json:"script_id,omitempty"`
	UserAgent          string            `json:"ua"`
	Session            string            `json:"session,omitempty"`
	ScriptURL          string            `json:"script_url,omitempty"`
	URL                string            `json:"url,omitempty"`
	PageOrigin         string            `json:"page_origin,omitempty"`
	Href               string            `json:"href,omitempty"`
	WindowURL          string            `json:"window_url,omitempty"`
	Referrer           string            `json:"referrer,omitempty"`
	AncestorOrigins    []string          `json:"ancestor_origins,omitempty"`
	RuntimeOverrides   map[string]any    `json:"runtime_overrides,omitempty"`
	AcceptLanguage     string            `json:"accept_language,omitempty"`
	Timezone           string            `json:"timezone,omitempty"`
	IP                 string            `json:"ip,omitempty"`
	ChallengeToken     string            `json:"challenge_token,omitempty"`
	ScriptName         string            `json:"script_name,omitempty"`
	Seed               uint64            `json:"seed,omitempty"`
	ForcePoolVariation bool              `json:"force_pool_variation,omitempty"`
	NowMS              int64             `json:"now_ms,omitempty"`
	DT                 map[string]any    `json:"dt,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
}

// kasadaSensorWire is the request as sent. The outer Script and ScriptID
// shadow the embedded request's fields, so the script travels only when the
// exchange asks for it.
type kasadaSensorWire struct {
	Mode string `json:"mode"`
	KasadaSensorRequest
	Script   string `json:"script,omitempty"`
	ScriptID string `json:"script_id,omitempty"`
}

// KasadaSensorResponse contains the encrypted payload and exact target-side
// headers and user agent. Attach every returned header to the target
// exchange, and send the low-entropy ClientHints (sec-ch-ua, sec-ch-ua-mobile,
// sec-ch-ua-platform) on every request; the other hints only to sites whose
// Accept-CH header asks for them.
type KasadaSensorResponse struct {
	Cost        float64           `json:"cost"`
	Payload     string            `json:"payload"`
	Headers     map[string]string `json:"headers,omitempty"`
	ClientHints map[string]string `json:"client_hints,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	DeviceID    string            `json:"device_id"`
	Session     string            `json:"session"`
	UserAgent   string            `json:"user_agent"`
	ScriptID    string            `json:"script_id"`
	CacheHit    bool              `json:"cache_hit"`
	DurationMS  int64             `json:"duration_ms"`
	Response    ResponseMeta      `json:"-"`
}

// Sensor generates a Kasada sensor payload and x-kpsdk-* headers. The p.js
// source is sent as its script_id and uploaded once on a cache miss.
func (s *KasadaService) Sensor(ctx context.Context, request *KasadaSensorRequest) (*KasadaSensorResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	scriptID, err := resolveScriptID(request.ScriptID, []byte(request.Script))
	if err != nil {
		return nil, err
	}
	script := request.Script
	wire := kasadaSensorWire{Mode: "sensor", KasadaSensorRequest: *request, ScriptID: scriptID}
	wire.KasadaSensorRequest.Script = ""
	wire.KasadaSensorRequest.ScriptID = ""
	result := new(KasadaSensorResponse)
	meta, err := s.client.solveScript(ctx, scriptExchange{
		path:        "/v1/solve/kasada",
		key:         "kasada:" + scriptID,
		hasScript:   script != "",
		scriptBytes: len(script),
		build: func(withScript bool) any {
			out := wire
			if withScript {
				out.Script = script
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

// KasadaCDRequest solves the follow-up CD challenge issued after a sensor
// exchange. Multi-word fields are encoded using the canonical snake_case API.
// Script is the same p.js source as the sensor call and travels as its
// script_id; set ScriptID instead when the source is not at hand.
type KasadaCDRequest struct {
	Script            string  `json:"script"`
	ScriptID          string  `json:"script_id,omitempty"`
	ST                int64   `json:"st"`
	CT                string  `json:"ct"`
	Domain            string  `json:"domain"`
	WorkTime          int64   `json:"work_time"`
	RST               int64   `json:"rst"`
	D                 int64   `json:"d"`
	ID                string  `json:"id"`
	Duration          float64 `json:"duration"`
	FC                string  `json:"fc"`
	Difficulty        int     `json:"difficulty,omitempty"`
	SubchallengeCount int     `json:"subchallenge_count,omitempty"`
	SeedSuffix        string  `json:"seed_suffix,omitempty"`
	ExtraToken        string  `json:"extra_token,omitempty"`
	IsMobile          bool    `json:"is_mobile,omitempty"`
	Seed              uint64  `json:"seed,omitempty"`
	NowMS             int64   `json:"now_ms,omitempty"`
}

type kasadaCDWire struct {
	Mode string `json:"mode"`
	KasadaCDRequest
	Script   string `json:"script,omitempty"`
	ScriptID string `json:"script_id,omitempty"`
}

// KasadaCDResponse contains the JSON string used as x-kpsdk-cd.
type KasadaCDResponse struct {
	Cost       float64      `json:"cost"`
	Payload    string       `json:"payload"`
	ScriptID   string       `json:"script_id"`
	DurationMS int64        `json:"duration_ms"`
	Response   ResponseMeta `json:"-"`
}

// CD solves a Kasada CD proof-of-work challenge.
func (s *KasadaService) CD(ctx context.Context, request *KasadaCDRequest) (*KasadaCDResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	scriptID, err := resolveScriptID(request.ScriptID, []byte(request.Script))
	if err != nil {
		return nil, err
	}
	script := request.Script
	wire := kasadaCDWire{Mode: "cd", KasadaCDRequest: *request, ScriptID: scriptID}
	wire.KasadaCDRequest.Script = ""
	wire.KasadaCDRequest.ScriptID = ""
	result := new(KasadaCDResponse)
	meta, err := s.client.solveScript(ctx, scriptExchange{
		path:        "/v1/solve/kasada",
		key:         "kasada:" + scriptID,
		hasScript:   script != "",
		scriptBytes: len(script),
		build: func(withScript bool) any {
			out := wire
			if withScript {
				out.Script = script
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
