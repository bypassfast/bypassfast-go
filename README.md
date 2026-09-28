# Bypass Fast Go SDK

[![Go](https://github.com/bypassfast/bypassfast-go/actions/workflows/test.yml/badge.svg)](https://github.com/bypassfast/bypassfast-go/actions/workflows/test.yml)

The official, dependency-free Go client for every production Bypass Fast
solver: Akamai, Kasada, Incapsula, and PerimeterX / HUMAN.

```sh
go get github.com/bypassfast/bypassfast-go
```

The module supports Go 1.22 and newer.

## Quick start

```go
package main

import (
	"context"
	"log"
	"os"

	bypassfast "github.com/bypassfast/bypassfast-go"
)

func main() {
	client, err := bypassfast.NewClient(os.Getenv("BYPASS_FAST_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.Kasada.Sensor(context.Background(), &bypassfast.KasadaSensorRequest{
		Script:    "<raw p.js body>",
		UserAgent: "<target-session Chrome user agent>",
		URL:       "https://www.example.com/checkout",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Submit result.Payload and every result.Headers entry to Kasada, then
	// use result.UserAgent verbatim for the protected request.
	_ = result
}
```

Create one client and reuse it across goroutines. Each call accepts a context,
so deadlines and cancellation flow through to the API.

## Solver methods

| Protection | SDK method | Artifact |
| --- | --- | --- |
| Akamai Bot Manager | `client.Akamai.Sensor` | `sensor_data`, session, exact UA/language |
| Akamai SBSD | `client.Akamai.SBSD` | encrypted SBSD body |
| Akamai Sec-CPT | `client.Akamai.CPT` | ten proof answers |
| Akamai sec-cpt challenge page | `client.Akamai.SecCPT` | `count` proof answers and the exact `/_sec/verify` body |
| Kasada sensor | `client.Kasada.Sensor` | encrypted payload and `x-kpsdk-*` headers |
| Kasada CD | `client.Kasada.CD` | `x-kpsdk-cd` proof body |
| Incapsula Reese84 | `client.Incapsula.Reese84` | sensor submission body and device session |
| Incapsula UTMVC | `client.Incapsula.UTMVC` | `___utmvc` cookie and submission path |
| PerimeterX init | `client.Perimeterx.Init` | HUMAN cookies and an opaque session |
| PerimeterX hold | `client.Perimeterx.SolveHold` | `Success`, refreshed cookies, retry advice |

`client.Balance` reads prepaid USD balance. `client.Solve` is a typed escape
hatch for newly added request fields, but the service methods are preferred.

### Akamai script handling

Pass raw JavaScript bytes in `AkamaiSensorRequest.Script` and
`AkamaiSBSDRequest.Script`; the SDK applies the base64 encoding required by the
API. After a sensor script succeeds, the client remembers only its SHA-256 and
uses `script_id` for later fresh sessions. If the server-side entry expired, it
automatically resends the supplied script once. Persist the returned
`ScriptID` if a new process should try the compact form immediately. On a new
process, set both `ScriptID` and `Script`: the ID is tried first and the raw
bytes are retained only for cache-miss fallback. `AkamaiScriptID` computes the
ID locally when needed.

### Incapsula script handling

The client remembers the SHA-256 associated with each successful mode and full
script URL. Repeated identical scripts use the URL-only cache path. Changed
bytes at the same URL are sent in full, and remote cache misses fall back to
the supplied script automatically.

### PerimeterX flow

`Init` returns the HUMAN cookies for a site; set every one of them and send
your own requests through the same proxy with the same user agent and
language. If a request comes back as a HUMAN block (JSON `428` with
`appId`/`blockScript`, or an HTML page containing `px-captcha`), call
`SolveHold` with the `Session` from `Init` and the response exactly as
received, then set the new cookies and retry once.

```go
session, err := client.Perimeterx.Init(ctx, &bypassfast.PerimeterxInitRequest{
	URL:       "https://www.example.com/en/booking",
	Proxy:     "http://user:pass@host:port",
	UserAgent: "<desktop Chrome user agent>",
})
// set session.Cookies, send your request; on a block:
hold, err := client.Perimeterx.SolveHold(ctx, &bypassfast.PerimeterxHoldRequest{
	Session: session.Session,
	Proxy:   "http://user:pass@host:port",
	Blocked: &bypassfast.PerimeterxBlockedResponse{
		URL: blockedURL, Method: "POST", Status: 428, Headers: blockedHeaders, Body: blockedBody,
	},
})
if err == nil && hold.ChangeExit() {
	// The rejection is tied to this exit: switch exit and start again from Init.
}
```

`Success` is false when the hold was rejected: the returned cookies are the
ones you already had and `Retry.ChangeExit` says whether to move to another
exit. That is not an error. PerimeterX bodies may reach 2 MiB (the HTML
block page rides in `Blocked.Body`); every other route keeps the 1 MiB limit.

## Errors and retries

```go
_, err := client.Kasada.CD(ctx, request)
if err != nil {
	var apiErr *bypassfast.APIError
	if errors.As(err, &apiErr) {
		log.Printf("solve failed: code=%s status=%d request_id=%s",
			apiErr.Code, apiErr.Response.StatusCode, apiErr.Response.RequestID)
	}
}
```

The default policy retries up to twice with jittered exponential backoff and
honors `Retry-After`. It only retries explicit non-2xx API responses known to
be non-billable and transient. It never retries a network/transport failure:
the connection may have failed after a non-idempotent solve completed. Configure
this behavior with `WithRetryPolicy`.

`429 solver_busy` means the solver task was at capacity, so it is retried
against a time budget instead of `MaxRetries`: for up to 45 seconds from the
start of the call by default. Each wait is at least the server's hint (the
`retry_after_ms` body field when present, otherwise `Retry-After`) plus full
jitter whose window doubles per retry, capped at 10 seconds and kept inside
the budget. No retry starts after the budget or the context deadline. Change
the budget with `WithSolverBusyRetryBudget`; zero, or `MaxRetries` zero,
disables it. `429 quota_exceeded` is never retried. Retries smooth a burst but
do not add capacity, so bound your own concurrency and ramp large batches.

Every successful result has a `Response` field containing status, request ID,
edge version, `Server-Timing`, and total attempt count. `APIError` provides the
same metadata plus the stable machine code. Errors intentionally exclude
response bodies because solver artifacts, cookies, and tokens are bearer
credentials.

## Transport behavior

- JSON requests of at least 1 KiB are gzip-compressed when compression saves
  bytes. Configure or disable this with `WithCompressionThreshold`.
- Decoded requests are rejected locally above the API's 1 MiB limit.
- Responses are bounded to 4 MiB and gzip-decoded independent of the supplied
  HTTP transport.
- Redirects are never followed, preventing `X-API-Key` from crossing origins.
- The default HTTP timeout is 65 seconds. A custom `*http.Client` can be passed
  with `WithHTTPClient`.
- Custom non-loopback base URLs must use HTTPS.

Never log request objects or successful solver responses. They can contain API
keys, proxy credentials, device sessions, target cookies, and challenge tokens.

## Releasing

Releases are published from the SDK's public mirror with standard semantic
version tags such as `v0.1.0`. Keep the tag and `Version` constant aligned.
