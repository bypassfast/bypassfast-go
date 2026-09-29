package bypassfast

import (
	"context"
)

// PerimeterxService provides the PerimeterX / HUMAN init and holdcaptcha
// modes. Init runs the page-sensor session through the caller's proxy and
// returns the HUMAN cookies plus an opaque session; SolveHold consumes the
// enforcement response the caller received on a protected request and
// returns refreshed cookies. The caller retries its own request afterwards;
// a rejected hold is Success false, not an error.
type PerimeterxService struct {
	client *Client
}

// PerimeterxPlatform selects the browser persona family.
type PerimeterxPlatform string

const (
	PerimeterxPlatformChromeWindows PerimeterxPlatform = "chrome-windows"
	PerimeterxPlatformChromeMac     PerimeterxPlatform = "chrome-mac"
)

// PerimeterxCookie is a cookie to install before the page fetch, or one the
// solver holds after an operation. Expires is a Unix timestamp in seconds,
// zero for a session cookie.
type PerimeterxCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}

// PerimeterxInitRequest runs the page-sensor session.
type PerimeterxInitRequest struct {
	// URL is the application page the user would open. Required.
	URL string
	// Proxy is the exit the whole flow must share: an http(s):// or
	// socks5(h):// URL with credentials. Required.
	Proxy string
	// UserAgent must be a desktop Chrome UA whose major has a device bundle.
	// Required.
	UserAgent string
	// AcceptLanguage defaults to "en-US,en;q=0.9".
	AcceptLanguage string
	// Timezone is an IANA zone matching the exit's region (default
	// America/New_York).
	Timezone string
	// Platform defaults to chrome-windows and must agree with UserAgent.
	Platform PerimeterxPlatform
	// Referer is the navigation referrer for the page fetch.
	Referer string
	// Headers are extra lower-case request headers for the page fetch.
	// Reserved headers (cookie, user-agent, sec-ch-*) are rejected.
	Headers map[string]string
	// Cookies are installed before the page fetch, for example cookies from
	// another solver.
	Cookies []PerimeterxCookie
	// AppID is the HUMAN application id (PX........). Inferred for the
	// supported hosts; required for any other site. The sensor is fetched
	// from origin + the app's first-party path, never discovered from the
	// page.
	AppID string
}

// PerimeterxBlockedResponse is the enforcement response the caller received.
type PerimeterxBlockedResponse struct {
	URL    string
	Method string
	// Status is the HTTP status (428 for the JSON API block, 403/200 for HTML).
	Status int
	// Headers are the response headers with lower-case names, comma-joined
	// when repeated. Set-Cookie values are applied to the session.
	Headers map[string]string
	// Body is the raw response body. The SDK sends it as UTF-8 text; use
	// BodyBase64 for bodies that are not valid text.
	Body string
	// BodyBase64, when true, marks Body as base64-encoded bytes.
	BodyBase64 bool
}

// PerimeterxHoldRequest solves the press-and-hold challenge inside an
// existing session.
type PerimeterxHoldRequest struct {
	// Session is the opaque value from the previous Init or SolveHold.
	// Required.
	Session string
	// Proxy must be the same exit used for Init and the blocked request.
	// Required.
	Proxy string
	// Blocked is the enforcement response exactly as received. Required.
	Blocked *PerimeterxBlockedResponse
	// URL is optional and only used when Blocked.URL is empty.
	URL string
	// UserAgent is optional; the session's UA is used when empty.
	UserAgent string
	// Headers describe the blocked request context (referer, origin), lower
	// case names.
	Headers map[string]string
}

// PerimeterxRetryAdvice tells the caller how to proceed after a rejected hold.
type PerimeterxRetryAdvice struct {
	ChangeExit bool   `json:"change_exit"`
	Reason     string `json:"reason"`
}

// PerimeterxResponse is the result of Init or SolveHold.
//
// Success true: install every cookie in Cookies and send (or retry once)
// your protected request. Success false: the hold was rejected; Cookies are
// the pre-hold cookies and Retry says what to do (usually change exit and
// call Init again). A rejected hold is not an error.
type PerimeterxResponse struct {
	Success  bool                   `json:"success"`
	Cookies  []PerimeterxCookie     `json:"cookies"`
	Session  string                 `json:"session"`
	Retry    *PerimeterxRetryAdvice `json:"retry,omitempty"`
	Cost     float64                `json:"cost"`
	Response ResponseMeta           `json:"-"`
}

// Rejected reports whether the hold was rejected.
func (r *PerimeterxResponse) Rejected() bool {
	return r != nil && !r.Success
}

// ChangeExit reports whether the caller should move to another exit and
// start again from Init.
func (r *PerimeterxResponse) ChangeExit() bool {
	return r != nil && !r.Success && r.Retry != nil && r.Retry.ChangeExit
}

type perimeterxBlockedWire struct {
	URL          string            `json:"url"`
	Method       string            `json:"method,omitempty"`
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"body_encoding,omitempty"`
}

type perimeterxWire struct {
	Mode           string                 `json:"mode"`
	URL            string                 `json:"url,omitempty"`
	Proxy          string                 `json:"proxy"`
	UserAgent      string                 `json:"ua,omitempty"`
	AcceptLanguage string                 `json:"accept_language,omitempty"`
	Timezone       string                 `json:"timezone,omitempty"`
	Platform       string                 `json:"platform,omitempty"`
	Referer        string                 `json:"referer,omitempty"`
	Headers        map[string]string      `json:"headers,omitempty"`
	Cookies        []PerimeterxCookie     `json:"cookies,omitempty"`
	AppID          string                 `json:"app_id,omitempty"`
	Session        string                 `json:"session,omitempty"`
	Blocked        *perimeterxBlockedWire `json:"blocked,omitempty"`
}

// Init runs the page-sensor session and returns cookies plus a session.
func (s *PerimeterxService) Init(ctx context.Context, request *PerimeterxInitRequest) (*PerimeterxResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	if request.URL == "" {
		return nil, &ValidationError{Field: "URL", Message: "must not be empty"}
	}
	if request.Proxy == "" {
		return nil, &ValidationError{Field: "Proxy", Message: "must not be empty"}
	}
	if request.UserAgent == "" {
		return nil, &ValidationError{Field: "UserAgent", Message: "must not be empty"}
	}
	wire := perimeterxWire{
		Mode:           "init",
		URL:            request.URL,
		Proxy:          request.Proxy,
		UserAgent:      request.UserAgent,
		AcceptLanguage: request.AcceptLanguage,
		Timezone:       request.Timezone,
		Platform:       string(request.Platform),
		Referer:        request.Referer,
		Headers:        request.Headers,
		Cookies:        append([]PerimeterxCookie(nil), request.Cookies...),
		AppID:          request.AppID,
	}
	return s.solve(ctx, wire)
}

// SolveHold solves the press-and-hold challenge behind a blocked response
// and returns refreshed cookies and the updated session.
func (s *PerimeterxService) SolveHold(ctx context.Context, request *PerimeterxHoldRequest) (*PerimeterxResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	if request.Session == "" {
		return nil, &ValidationError{Field: "Session", Message: "must not be empty"}
	}
	if request.Proxy == "" {
		return nil, &ValidationError{Field: "Proxy", Message: "must not be empty"}
	}
	if request.Blocked == nil {
		return nil, &ValidationError{Field: "Blocked", Message: "must not be nil"}
	}
	if request.Blocked.URL == "" && request.URL == "" {
		return nil, &ValidationError{Field: "Blocked.URL", Message: "must not be empty when URL is empty"}
	}
	blocked := &perimeterxBlockedWire{
		URL:     request.Blocked.URL,
		Method:  request.Blocked.Method,
		Status:  request.Blocked.Status,
		Headers: request.Blocked.Headers,
		Body:    request.Blocked.Body,
	}
	if request.Blocked.BodyBase64 {
		blocked.BodyEncoding = "base64"
	}
	wire := perimeterxWire{
		Mode:      "holdcaptcha",
		URL:       request.URL,
		Proxy:     request.Proxy,
		UserAgent: request.UserAgent,
		Headers:   request.Headers,
		Session:   request.Session,
		Blocked:   blocked,
	}
	return s.solve(ctx, wire)
}

func (s *PerimeterxService) solve(ctx context.Context, wire perimeterxWire) (*PerimeterxResponse, error) {
	result := new(PerimeterxResponse)
	meta, err := s.client.doJSONWithLimit(ctx, "POST", "/v1/solve/perimeterx", wire, result, maxPerimeterxRequestBytes)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}
