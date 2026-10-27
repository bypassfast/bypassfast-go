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

### Script handling

Every script-bearing call (Akamai sensor and SBSD, Kasada sensor and CD,
Incapsula Reese84 and UTMVC) travels hash-first: the request carries the
script's SHA-256 as `script_id` and no script. The API keeps every script it
has been sent for days, so the body is only needed when nobody has sent that
script yet; the API then answers `409 script_cache_miss` (not billed) and the
SDK repeats the call once with the script. A new script version costs one
extra round trip, once, fleet-wide: an Akamai sensor request is about 1 KB
on the wire instead of hundreds of KB, a Kasada one about 1 KB instead of
700 KB. After a miss the client sends the script directly for a minute, so a
burst of solves for a brand-new script uploads it once.

Keep passing the script exactly as today: raw bytes in
`AkamaiSensorRequest.Script` and `AkamaiSBSDRequest.Script` (the SDK applies
the base64 encoding the API requires), raw text in the Kasada and Incapsula
requests. When the script is not at hand, set `ScriptID` instead (every
script-bearing response returns it, and `ScriptID(raw)` computes it); a cache
miss is then returned as the `APIError`. A script the API could never accept
(over 1 MiB encoded) is refused locally before any round trip.

### Client hints

Every solve returns `ClientHints`: the UA client hints of the device the
payload describes, as Chrome sends them. Send `sec-ch-ua`, `sec-ch-ua-mobile`
and `sec-ch-ua-platform` on every request of the session, and the other
hints (`sec-ch-ua-platform-version`, `sec-ch-ua-full-version-list`, ...)
only to sites whose `Accept-CH` response header asks for them. The map's
iteration order is not the header order.

### Akamai telemetry header

Some sites protect their API calls with an `Akamai-BM-Telemetry` request
header instead of a sensor post. Set `AkamaiSensorRequest.Telemetry` and
the response carries the ready-to-send header value in `Telemetry`, beside
`SensorData`.

### Akamai SBSD on a normal page

A normal `200` page can run SBSD too: a first-party script whose URL carries
`?v=` sits next to the sensor script, and the page response sets `bm_so`. Post
it as part of the page, before any protected request: after the first sensor
post, call `client.Akamai.SBSD` with the sensor's `Session` and `SBSDO` set to
the `bm_so` value, POST `{"body": ...}` to the script path without its query,
continue the sensor with the `Session` it returned, then, after the page's
third sensor post, ask for the two telemetry posts with `Post: "telemetry"`
(wait `WaitMS`, or set `Pace`). A refused telemetry call is a 409 whose
`APIError.Reason` says what to do: `no_input` means post the page's next
sensor and ask again (waiting alone never makes it due), `complete` means
send no more. The full order is on the [SBSD docs page](https://bypass.fast/docs/solvers/akamai/sbsd#inline-sbsd-on-a-normal-page).
A client that skips it still gets a valid `_abck`, and the protected endpoint
answers `403` instead.

### Akamai sensor pacing

A page posts its sensors seconds apart, and protected endpoints score a
session whose sensors arrive a fraction of a second apart. Either wait
2.5-4 s between the sensor calls of one session, or set
`AkamaiSensorRequest.Pace` on them: the API then holds each continuation
response until that interval has passed (never more than 6 s, never the
first call), and the call simply takes longer.

### PerimeterX flow

`Init` returns the HUMAN cookies for a site; set every one of them and send
your own requests through the same proxy with the same user agent and
language. If a request comes back as a HUMAN block (JSON `428` with
`appId`/`blockScript`, or an HTML page containing `px-captcha`), call
`SolveHold` with the `Session` from `Init`, the response exactly as
received and the cookies you hold for the site at that point, then set the
returned cookies and retry once.

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
	Cookies: cookiesHeldAtTheBlock, // your jar for the site, HUMAN's cookies included
})
if err == nil && !hold.Success {
	// Stop. A rejected hold is billed and may reflect an app-wide HUMAN rule.
}
```

`Success` is false when the hold was rejected: the returned cookies are the
ones you already had. Stop unless `Retry` explicitly supplies a safe action;
blindly changing exits can amplify an app-wide rejection. That is not an
error. PerimeterX bodies may reach 2 MiB (the HTML block page rides in
`Blocked.Body`); every other route keeps the 1 MiB limit.

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
- Decoded requests are rejected locally above the API's 1 MiB limit (2 MiB
  for PerimeterX, whose hold requests carry the block page).
- Responses are bounded to 4 MiB and gzip-decoded independent of the supplied
  HTTP transport.
- Redirects are never followed, preventing `X-API-Key` from crossing origins.
- Each attempt is bounded by a per-route timeout: 65 seconds by default
  (`WithTimeout`) and 155 seconds for PerimeterX (`WithPerimeterxTimeout`),
  whose solves run a real press-and-hold and may queue. Bound a whole call,
  retries included, with the context. A custom `*http.Client` can be passed
  with `WithHTTPClient`; its own `Timeout`, if set, applies as well.
- Custom non-loopback base URLs must use HTTPS.

Never log request objects or successful solver responses. They can contain API
keys, proxy credentials, device sessions, target cookies, and challenge tokens.

## Releasing

Releases are tagged in this repository with standard semantic version tags
such as `v0.2.1`; see [CHANGELOG.md](CHANGELOG.md). Keep the tag and the
`Version` constant aligned. `v0.1.0` is retracted: it was a pre-release
prototype with a different API surface.

## License

MIT. See [LICENSE](LICENSE).
