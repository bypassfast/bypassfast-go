package bypassfast

import "context"

// DataDomeService provides complete target-session solves.
type DataDomeService struct {
	client *Client
}

// DataDomeRequest describes the target session. Proxy may contain credentials;
// the SDK never includes request bodies in returned errors.
type DataDomeRequest struct {
	Target         string `json:"target"`
	Proxy          string `json:"proxy,omitempty"`
	Cookie         string `json:"cookie,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	Profile        uint32 `json:"profile,omitempty"`
}

// SessionCookie is a cookie to install in the caller's target-side jar.
type SessionCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// DataDomeResponse contains a verified target-side session. Install every
// cookie, then keep the returned user agent, proxy, and TLS identity aligned.
type DataDomeResponse struct {
	Cost             float64         `json:"cost"`
	Payload          string          `json:"payload"`
	Cookie           string          `json:"cookie"`
	Cookies          []SessionCookie `json:"cookies"`
	UserAgent        string          `json:"user_agent"`
	Kind             string          `json:"kind"`
	Backend          string          `json:"backend"`
	Verified         bool            `json:"verified"`
	InitialStatus    int             `json:"initial_status"`
	ChallengeStatus  int             `json:"challenge_status,omitempty"`
	SubmitStatus     int             `json:"submit_status,omitempty"`
	VerifyStatus     int             `json:"verify_status,omitempty"`
	RechallengeCount int             `json:"rechallenge_count,omitempty"`
	Warnings         []string        `json:"warnings,omitempty"`
	DurationMS       int64           `json:"duration_ms"`
	Response         ResponseMeta    `json:"-"`
}

// Solve performs and verifies a complete DataDome target session.
func (s *DataDomeService) Solve(ctx context.Context, request *DataDomeRequest) (*DataDomeResponse, error) {
	if request == nil {
		return nil, &ValidationError{Field: "request", Message: "must not be nil"}
	}
	result := new(DataDomeResponse)
	meta, err := s.client.doJSON(ctx, "POST", "/v1/solve/datadome", request, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}
