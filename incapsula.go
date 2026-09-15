package bypassfast

import (
	"context"
)

// IncapsulaService provides Imperva/Incapsula Reese84 and UTMVC modes.
type IncapsulaService struct {
	client *Client
}

// IncapsulaReese84Request generates a Reese84 sensor payload. Script is raw
// JavaScript and is omitted automatically after this Client has registered the
// same content at the same ScriptURL.
type IncapsulaReese84Request struct {
	Script         string
	UserAgent      string
	ScriptURL      string
	URL            string
	AcceptLanguage string
	IP             string
	POW            string
	OldToken       string
	Session        string
	Headers        map[string]string
	// DocumentHTML is the challenged page body from which Script was
	// discovered. Send it for dynamic Reese84 pages: some variants fingerprint
	// every script element in this document, including tenant static resources
	// that do not appear in the loader itself.
	DocumentHTML string
	// DocumentScriptSourceGroups is the pre-extracted advanced form of
	// DocumentHTML. Most callers should set DocumentHTML and let the API parse
	// the browser collector order.
	DocumentScriptSourceGroups [][]string
}

// IncapsulaUTMVCRequest generates the ___utmvc cookie workflow.
type IncapsulaUTMVCRequest struct {
	Script         string
	UserAgent      string
	ScriptURL      string
	URL            string
	AcceptLanguage string
	IP             string
	Session        string
	Headers        map[string]string
	SessionIDs     []string
}

// IncapsulaResponse contains fields shared by Reese84 and UTMVC. UTMVC fills
// Cookie, CookieName, and SubmitPath; Reese84 fills DeviceID and Session.
type IncapsulaResponse struct {
	Cost       float64      `json:"cost"`
	Payload    string       `json:"payload"`
	Backend    string       `json:"backend"`
	DeviceID   string       `json:"device_id,omitempty"`
	Session    string       `json:"session,omitempty"`
	DurationMS int64        `json:"duration_ms"`
	Cookie     string       `json:"cookie,omitempty"`
	CookieName string       `json:"cookie_name,omitempty"`
	SubmitPath string       `json:"submit_path,omitempty"`
	Response   ResponseMeta `json:"-"`
}

type incapsulaWire struct {
	Mode                       string            `json:"mode"`
	Script                     string            `json:"script,omitempty"`
	UserAgent                  string            `json:"ua"`
	ScriptURL                  string            `json:"script_url"`
	URL                        string            `json:"url"`
	AcceptLanguage             string            `json:"accept_language,omitempty"`
	IP                         string            `json:"ip,omitempty"`
	POW                        string            `json:"pow,omitempty"`
	OldToken                   string            `json:"old_token,omitempty"`
	Session                    string            `json:"session,omitempty"`
	Headers                    map[string]string `json:"headers,omitempty"`
	SessionIDs                 []string          `json:"session_ids,omitempty"`
	DocumentHTML               string            `json:"document_html,omitempty"`
	DocumentScriptSourceGroups [][]string        `json:"document_script_source_groups,omitempty"`
}

// Reese84 generates an Incapsula Reese84 sensor payload.
func (s *IncapsulaService) Reese84(ctx context.Context, request *IncapsulaReese84Request) (*IncapsulaResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := incapsulaWire{
		Mode:                       "reese84",
		Script:                     request.Script,
		UserAgent:                  request.UserAgent,
		ScriptURL:                  request.ScriptURL,
		URL:                        request.URL,
		AcceptLanguage:             request.AcceptLanguage,
		IP:                         request.IP,
		POW:                        request.POW,
		OldToken:                   request.OldToken,
		Session:                    request.Session,
		Headers:                    request.Headers,
		DocumentHTML:               request.DocumentHTML,
		DocumentScriptSourceGroups: cloneIncapsulaStringGroups(request.DocumentScriptSourceGroups),
	}
	return s.solve(ctx, wire)
}

func cloneIncapsulaStringGroups(groups [][]string) [][]string {
	if len(groups) == 0 {
		return nil
	}
	out := make([][]string, len(groups))
	for index, group := range groups {
		out[index] = append([]string(nil), group...)
	}
	return out
}

// UTMVC generates the ___utmvc cookie and submission path.
func (s *IncapsulaService) UTMVC(ctx context.Context, request *IncapsulaUTMVCRequest) (*IncapsulaResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	wire := incapsulaWire{
		Mode:           "utmvc",
		Script:         request.Script,
		UserAgent:      request.UserAgent,
		ScriptURL:      request.ScriptURL,
		URL:            request.URL,
		AcceptLanguage: request.AcceptLanguage,
		IP:             request.IP,
		Session:        request.Session,
		Headers:        request.Headers,
		SessionIDs:     request.SessionIDs,
	}
	return s.solve(ctx, wire)
}

func (s *IncapsulaService) solve(ctx context.Context, wire incapsulaWire) (*IncapsulaResponse, error) {
	fullScript := wire.Script
	cacheKey := "incapsula:" + wire.Mode + ":" + wire.ScriptURL
	scriptHash := ""
	usedCompactScript := false
	if fullScript != "" {
		scriptHash = sha256Hex([]byte(fullScript))
		usedCompactScript = s.client.scripts.matches(cacheKey, scriptHash)
		if usedCompactScript {
			wire.Script = ""
		}
	}

	result := new(IncapsulaResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/incapsula", wire, result)
	if err != nil && usedCompactScript &&
		(IsErrorCode(err, "script_cache_miss") || IsErrorCode(err, "script_cache_unavailable")) {
		priorAttempts := meta.Attempts
		wire.Script = fullScript
		result = new(IncapsulaResponse)
		meta, err = s.client.doJSON(ctx, "POST", "/v1/solve/incapsula", wire, result)
		applyFallbackAttempts(&meta, err, priorAttempts)
	}
	if err != nil {
		return nil, err
	}
	result.Response = meta
	if scriptHash != "" {
		s.client.scripts.put(cacheKey, scriptHash)
	}
	return result, nil
}
