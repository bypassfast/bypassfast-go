package bypassfast

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// AkamaiService provides Akamai Bot Manager solve modes.
type AkamaiService struct {
	client *Client
}

// AkamaiSensorConfig overrides generated interaction families in local debug mode.
type AkamaiSensorConfig struct {
	Mouse    bool `json:"mouse"`
	Keyboard bool `json:"keyboard"`
	Touch    bool `json:"touch"`
	Beta     bool `json:"beta"`
}

// AkamaiSensorRequest generates Bot Manager sensor_data. Script contains raw
// JavaScript bytes; the SDK performs the required base64 encoding.
type AkamaiSensorRequest struct {
	URL            string
	UserAgent      string
	ABCK           string
	BMSZ           string
	Script         []byte
	ScriptID       string
	ScriptURL      string
	Config         AkamaiSensorConfig
	AcceptLanguage string
	Language       string
	Timezone       string
	Session        string
	Device         map[string]any
	Debug          bool
}

// AkamaiSensorResponse contains the artifact and exact client identity that
// must be used for the target exchange.
type AkamaiSensorResponse struct {
	Cost       float64         `json:"cost"`
	Success    bool            `json:"success"`
	SensorData string          `json:"sensor_data"`
	UserAgent  string          `json:"ua"`
	Session    string          `json:"session"`
	Language   string          `json:"language"`
	ScriptID   string          `json:"script_id"`
	Debug      json.RawMessage `json:"debug,omitempty"`
	Response   ResponseMeta    `json:"-"`
}

type akamaiSensorWire struct {
	Mode           string              `json:"mode"`
	URL            string              `json:"url"`
	UserAgent      string              `json:"ua"`
	ABCK           string              `json:"abck"`
	BMSZ           string              `json:"bm_sz"`
	Script         string              `json:"script,omitempty"`
	ScriptID       string              `json:"script_id,omitempty"`
	ScriptURL      string              `json:"script_url"`
	Config         *AkamaiSensorConfig `json:"config,omitempty"`
	AcceptLanguage string              `json:"accept_language,omitempty"`
	Language       string              `json:"language,omitempty"`
	Timezone       string              `json:"timezone,omitempty"`
	Session        string              `json:"session,omitempty"`
	Device         map[string]any      `json:"device,omitempty"`
	Debug          bool                `json:"debug,omitempty"`
}

// Sensor generates Akamai Bot Manager sensor_data. After a successful
// script-bearing call, this Client automatically uses the compact script_id
// form for matching scripts and resends the full script on a remote cache miss.
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
		Device:         request.Device,
		Debug:          request.Debug,
	}
	if request.Debug {
		wire.Config = &request.Config
	}

	var scriptID string
	usedCompactScript := false
	if request.Session == "" {
		scriptID = strings.ToLower(request.ScriptID)
		explicitScriptID := scriptID != ""
		if scriptID != "" && !validSHA256(scriptID) {
			return nil, &ValidationError{Field: "script_id", Message: "must be a 64-character SHA-256 hex digest"}
		}
		if len(request.Script) > 0 {
			computed := sha256Hex(request.Script)
			if scriptID != "" && scriptID != computed {
				return nil, &ValidationError{Field: "script_id", Message: "does not match Script bytes"}
			}
			scriptID = computed
		}
		wire.ScriptID = scriptID
		usedCompactScript = len(request.Script) > 0 && (explicitScriptID || s.client.scripts.matches("akamai:"+scriptID, scriptID))
		if len(request.Script) > 0 && !usedCompactScript {
			wire.Script = base64.StdEncoding.EncodeToString(request.Script)
		}
	}

	result := new(AkamaiSensorResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
	if err != nil && usedCompactScript && len(request.Script) > 0 &&
		(IsErrorCode(err, "script_cache_miss") || IsErrorCode(err, "script_cache_unavailable")) {
		priorAttempts := meta.Attempts
		wire.Script = base64.StdEncoding.EncodeToString(request.Script)
		result = new(AkamaiSensorResponse)
		meta, err = s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
		applyFallbackAttempts(&meta, err, priorAttempts)
	}
	if err != nil {
		return nil, err
	}
	result.Response = meta
	if result.ScriptID == "" {
		result.ScriptID = scriptID
	}
	if scriptID != "" {
		s.client.scripts.put("akamai:"+scriptID, scriptID)
	}
	return result, nil
}

// AkamaiSBSDRequest generates the encrypted Akamai side-band payload. Script
// contains raw JavaScript bytes and is base64-encoded by the SDK.
type AkamaiSBSDRequest struct {
	URL             string
	UserAgent       string
	Script          []byte
	ScriptURL       string
	SBSDO           string
	AcceptLanguage  string
	Language        string
	Timezone        string
	UUID            string
	Device          map[string]any
	ResourceURLs    []string
	DOMResourceURLs []string
	Debug           bool
}

// AkamaiSBSDResponse contains the complete encrypted body to submit upstream.
type AkamaiSBSDResponse struct {
	Cost     float64         `json:"cost"`
	Success  bool            `json:"success"`
	Body     string          `json:"body"`
	Debug    json.RawMessage `json:"debug,omitempty"`
	Response ResponseMeta    `json:"-"`
}

// SBSD generates an encrypted side-band payload.
func (s *AkamaiService) SBSD(ctx context.Context, request *AkamaiSBSDRequest) (*AkamaiSBSDResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := struct {
		Mode            string         `json:"mode"`
		URL             string         `json:"url"`
		UserAgent       string         `json:"ua"`
		Script          string         `json:"script"`
		ScriptURL       string         `json:"script_url"`
		SBSDO           string         `json:"sbsd_o"`
		AcceptLanguage  string         `json:"accept_language,omitempty"`
		Language        string         `json:"language,omitempty"`
		Timezone        string         `json:"timezone,omitempty"`
		UUID            string         `json:"uuid,omitempty"`
		Device          map[string]any `json:"device,omitempty"`
		ResourceURLs    []string       `json:"resource_urls,omitempty"`
		DOMResourceURLs []string       `json:"dom_resource_urls,omitempty"`
		Debug           bool           `json:"debug,omitempty"`
	}{
		Mode:            "sbsd",
		URL:             request.URL,
		UserAgent:       request.UserAgent,
		Script:          base64.StdEncoding.EncodeToString(request.Script),
		ScriptURL:       request.ScriptURL,
		SBSDO:           request.SBSDO,
		AcceptLanguage:  request.AcceptLanguage,
		Language:        request.Language,
		Timezone:        request.Timezone,
		UUID:            request.UUID,
		Device:          request.Device,
		ResourceURLs:    request.ResourceURLs,
		DOMResourceURLs: request.DOMResourceURLs,
		Debug:           request.Debug,
	}
	result := new(AkamaiSBSDResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}

// AkamaiCPTRequest solves the pure-compute Sec-CPT challenge.
type AkamaiCPTRequest struct {
	Token      string
	Difficulty int
	Debug      bool
}

// AkamaiCPTResponse contains the ten Sec-CPT proof answers.
type AkamaiCPTResponse struct {
	Cost     float64         `json:"cost"`
	Success  bool            `json:"success"`
	Answers  []string        `json:"answers"`
	Debug    json.RawMessage `json:"debug,omitempty"`
	Response ResponseMeta    `json:"-"`
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
		Debug      bool   `json:"debug,omitempty"`
	}{Mode: "cpt", Token: request.Token, Difficulty: request.Difficulty, Debug: request.Debug}
	result := new(AkamaiCPTResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/akamai", wire, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// AkamaiScriptID returns the script_id for raw Akamai JavaScript bytes. Set
// both ScriptID and Script on a fresh Client to try the compact remote-cache
// path first while retaining the raw bytes for automatic cache-miss fallback.
func AkamaiScriptID(rawScript []byte) string {
	return sha256Hex(rawScript)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
