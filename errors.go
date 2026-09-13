package bypassfast

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ResponseMeta contains value-free diagnostics returned with a solve.
type ResponseMeta struct {
	StatusCode   int
	RequestID    string
	Edge         string
	ServerTiming string
	Attempts     int
}

// ValidationError reports a request rejected locally before any API call.
type ValidationError struct {
	Field   string
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Field == "" {
		return "bypassfast: " + e.Message
	}
	return fmt.Sprintf("bypassfast: invalid %s: %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// RequestError reports a failure to construct or send an HTTP request. The
// SDK deliberately does not retry these failures because a solve may have
// completed before a connection failed.
type RequestError struct {
	Operation string
	Cause     error
}

func (e *RequestError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("bypassfast: %s: %v", e.Operation, e.Cause)
}

func (e *RequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ResponseError reports an unreadable, unsupported, or malformed successful
// response. Response bodies are intentionally omitted because solver outputs
// can contain bearer credentials.
type ResponseError struct {
	Response ResponseMeta
	Cause    error
}

func (e *ResponseError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Response.RequestID != "" {
		return fmt.Sprintf("bypassfast: invalid response (status %d, request %s): %v", e.Response.StatusCode, e.Response.RequestID, e.Cause)
	}
	return fmt.Sprintf("bypassfast: invalid response (status %d): %v", e.Response.StatusCode, e.Cause)
}

func (e *ResponseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// APIError is a non-2xx response from Bypass Fast. Code is the stable machine
// contract from either "error" or Akamai's legacy "error_code" field.
type APIError struct {
	Response   ResponseMeta
	Code       string
	Message    string
	Stage      string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	detail := e.Code
	if detail == "" {
		detail = "http_error"
	}
	if e.Response.RequestID != "" {
		return fmt.Sprintf("bypassfast: %s (status %d, request %s)", detail, e.Response.StatusCode, e.Response.RequestID)
	}
	return fmt.Sprintf("bypassfast: %s (status %d)", detail, e.Response.StatusCode)
}

// Retryable reports whether retrying this explicit API response is safe and
// recommended. It does not imply that transport errors are retryable.
func (e *APIError) Retryable() bool {
	if e == nil {
		return false
	}
	switch e.Code {
	case "quota_exceeded", "billing_disabled", "hard_block", "unsupported_challenge",
		"unsupported_script", "solve_failed", "not_verified", "solve_timeout",
		"script_cache_miss":
		return false
	case "solver_busy", "rate_limited", "quota_unavailable", "replay_unavailable",
		"edge_unavailable", "solver_unavailable", "api_key_store_unavailable",
		"org_status_unavailable", "cf_allowlist_unavailable", "request_cancelled",
		"internal", "internal_error", "no_devices_available", "device_unavailable",
		"script_cache_unavailable", "captcha_builder_unavailable":
		return true
	}
	return e.Response.StatusCode >= 500 && e.Response.StatusCode <= 599
}

// IsErrorCode reports whether err or an error in its chain is an APIError with
// the given stable machine code.
func IsErrorCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

func decodeAPIError(payload []byte) *APIError {
	var wire struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
		Stage     string `json:"stage"`
	}
	if json.Unmarshal(payload, &wire) != nil {
		return &APIError{Code: "http_error"}
	}
	code := wire.Error
	if code == "" {
		code = wire.ErrorCode
	}
	if code == "" {
		code = "http_error"
	}
	return &APIError{Code: code, Message: wire.Message, Stage: wire.Stage}
}
