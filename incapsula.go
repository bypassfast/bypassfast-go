package bypassfast

import (
	"context"
)

// IncapsulaService provides Imperva/Incapsula Reese84 and UTMVC modes.
type IncapsulaService struct {
	client *Client
}

// IncapsulaReese84Request generates a Reese84 sensor payload. Script is raw
// JavaScript; the SDK sends only its SHA-256 as script_id and uploads the
// script once, only when the API has never seen it. ScriptID may be set
// instead of Script when the source is not at hand.
type IncapsulaReese84Request struct {
	Script         string
	ScriptID       string
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

// IncapsulaUTMVCRequest generates the ___utmvc cookie workflow. Script
// travels as its script_id like Reese84.
type IncapsulaUTMVCRequest struct {
	Script         string
	ScriptID       string
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
// ScriptID is the digest of the script the solve used. ClientHints are the
// UA client hints of the device: send the low-entropy ones (sec-ch-ua,
// sec-ch-ua-mobile, sec-ch-ua-platform) on every request and the others only
// to sites whose Accept-CH header asks for them.
type IncapsulaResponse struct {
	Cost        float64           `json:"cost"`
	Payload     string            `json:"payload"`
	Backend     string            `json:"backend"`
	DeviceID    string            `json:"device_id,omitempty"`
	Session     string            `json:"session,omitempty"`
	ScriptID    string            `json:"script_id,omitempty"`
	ClientHints map[string]string `json:"client_hints,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
	Cookie      string            `json:"cookie,omitempty"`
	CookieName  string            `json:"cookie_name,omitempty"`
	SubmitPath  string            `json:"submit_path,omitempty"`
	Response    ResponseMeta      `json:"-"`
}

type incapsulaWire struct {
	Mode                       string            `json:"mode"`
	Script                     string            `json:"script,omitempty"`
	ScriptID                   string            `json:"script_id,omitempty"`
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
	return s.solve(ctx, wire, request.Script, request.ScriptID)
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
		UserAgent:      request.UserAgent,
		ScriptURL:      request.ScriptURL,
		URL:            request.URL,
		AcceptLanguage: request.AcceptLanguage,
		IP:             request.IP,
		Session:        request.Session,
		Headers:        request.Headers,
		SessionIDs:     request.SessionIDs,
	}
	return s.solve(ctx, wire, request.Script, request.ScriptID)
}

// solve sends the script hash-first. Without a script or a script_id the
// request is still sent: the API resolves a known script_url on its own and
// answers 409 script_cache_miss when it cannot.
func (s *IncapsulaService) solve(ctx context.Context, wire incapsulaWire, script, explicitID string) (*IncapsulaResponse, error) {
	scriptID, err := resolveScriptID(explicitID, []byte(script))
	if err != nil {
		return nil, err
	}
	wire.ScriptID = scriptID
	result := new(IncapsulaResponse)
	meta, err := s.client.solveScript(ctx, scriptExchange{
		path:        "/v1/solve/incapsula",
		key:         "incapsula:" + wire.Mode + ":" + scriptID,
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
