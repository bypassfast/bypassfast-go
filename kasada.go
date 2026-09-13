package bypassfast

import "context"

// KasadaService provides Kasada sensor and proof-of-work modes.
type KasadaService struct {
	client *Client
}

// KasadaSensorRequest generates a full Kasada payload. Script is the raw p.js
// source; unlike Akamai, it must not be base64-encoded.
type KasadaSensorRequest struct {
	Script             string            `json:"script"`
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
	IP                 string            `json:"ip,omitempty"`
	ChallengeToken     string            `json:"challenge_token,omitempty"`
	ScriptName         string            `json:"script_name,omitempty"`
	Seed               uint64            `json:"seed,omitempty"`
	ForcePoolVariation bool              `json:"force_pool_variation,omitempty"`
	NowMS              int64             `json:"now_ms,omitempty"`
	DT                 map[string]any    `json:"dt,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
}

type kasadaSensorWire struct {
	Mode string `json:"mode"`
	KasadaSensorRequest
}

// KasadaSensorResponse contains the encrypted payload and exact target-side
// headers and user agent. Attach every returned header to the target exchange.
type KasadaSensorResponse struct {
	Cost       float64           `json:"cost"`
	Payload    string            `json:"payload"`
	Headers    map[string]string `json:"headers,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
	DeviceID   string            `json:"device_id"`
	Session    string            `json:"session"`
	UserAgent  string            `json:"user_agent"`
	CacheHit   bool              `json:"cache_hit"`
	DurationMS int64             `json:"duration_ms"`
	Response   ResponseMeta      `json:"-"`
}

// Sensor generates a Kasada sensor payload and x-kpsdk-* headers.
func (s *KasadaService) Sensor(ctx context.Context, request *KasadaSensorRequest) (*KasadaSensorResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	result := new(KasadaSensorResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/kasada", kasadaSensorWire{
		Mode:                "sensor",
		KasadaSensorRequest: *request,
	}, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}

// KasadaCDRequest solves the follow-up CD challenge issued after a sensor
// exchange. Multi-word fields are encoded using the canonical snake_case API.
type KasadaCDRequest struct {
	Script            string  `json:"script"`
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
}

// KasadaCDResponse contains the JSON string used as x-kpsdk-cd.
type KasadaCDResponse struct {
	Cost       float64      `json:"cost"`
	Payload    string       `json:"payload"`
	DurationMS int64        `json:"duration_ms"`
	Response   ResponseMeta `json:"-"`
}

// CD solves a Kasada CD proof-of-work challenge.
func (s *KasadaService) CD(ctx context.Context, request *KasadaCDRequest) (*KasadaCDResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	result := new(KasadaCDResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/kasada", kasadaCDWire{
		Mode:            "cd",
		KasadaCDRequest: *request,
	}, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}
