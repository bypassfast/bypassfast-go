# Changelog

All notable changes to the Bypass Fast Go SDK are recorded here. The module
follows [Semantic Versioning](https://semver.org/).

## 0.3.0 - 2026-10-27

- Every script-bearing call travels hash-first. `Akamai.Sensor`, `Akamai.SBSD`,
  `Kasada.Sensor`, `Kasada.CD`, `Incapsula.Reese84` and `Incapsula.UTMVC` send
  the script's SHA-256 as `script_id` and no script; the API keeps every
  script it has been sent, so the body is uploaded only when nobody has sent
  that script yet (409 `script_cache_miss`, not billed), in one automatic
  resend. An Akamai sensor request goes from hundreds of KB to about 1 KB on
  the wire, a Kasada one from about 700 KB. After a miss the client sends the
  script directly for a minute, so a burst of solves for a new script uploads
  it once. `ScriptID` computes the digest; `AkamaiScriptID` remains.
- Kasada and Incapsula requests accept `ScriptID` instead of `Script`, and
  every script-bearing response returns `ScriptID`.
- Every solve returns `ClientHints`, the UA client hints of the device the
  payload describes. Send `sec-ch-ua`, `sec-ch-ua-mobile` and
  `sec-ch-ua-platform` on every request, and the others only to sites whose
  `Accept-CH` header asks for them.
- Akamai: `AkamaiSensorRequest.Telemetry` returns the `Akamai-BM-Telemetry`
  header value in `AkamaiSensorResponse.Telemetry`, for sites that protect
  their API calls with that header instead of a sensor post.
  `AkamaiSensorResponse.PacedMS` reports how long a paced response was held.
- A script the API could never accept (over 1 MiB encoded) is refused locally
  as a `ValidationError` on `script` before any round trip.
- PerimeterX: `PerimeterxResponse.AcceptLanguage` is the Accept-Language the
  session runs as. Without `AcceptLanguage` in `Init` the API draws a real
  Chrome value for the proxy exit's country; the SDK keeps your own value
  when you set one. Send every request of the session with `UserAgent` and
  `AcceptLanguage`.
- PerimeterX: `PerimeterxPlatformAuto` on `PerimeterxInitRequest.Platform`
  has the solver draw each session's platform (Windows or macOS) and,
  without `UserAgent`, a current Chrome major;
  `PerimeterxResponse.Platform` reports the draw.
- Akamai: `AkamaiSensorRequest.Pace` asks the API to hold each sensor
  response until a person's interval (2.5-4 s) has passed since the
  previous sensor.

## 0.2.1 - 2026-10-05

- PerimeterX calls get their own per-attempt timeout, 155 s by default
  (`WithPerimeterxTimeout`). Every other route keeps 65 s, now set with
  `WithTimeout` instead of the HTTP client's `Timeout`. A hold the solver
  needs a minute or more for no longer fails on the client while the server
  completes and bills it.
- `Client.Solve` with `SolverPerimeterx` uses the PerimeterX request limit
  (2 MiB) and timeout, like the typed methods.
- Removed the Akamai `Debug`, `Config` and `Device` request options and the
  `Debug` response field: the hosted API rejects them with 403
  `debug_forbidden` / `device_override_forbidden`.
- Licensed under the MIT License.
- `v0.1.0` is retracted (see `go.mod`).

## 0.2.0 - 2026-10-03

- Akamai (sensor, SBSD, CPT, sec-cpt), Kasada (sensor, CD), Incapsula
  (Reese84, UTMVC) and PerimeterX / HUMAN (init, hold) behind one wire
  contract, with automatic script reuse, retries for retryable API errors, a
  solver_busy time budget, gzip request compression and bounded responses.

## 0.1.0

Retracted. A pre-release prototype with a different API surface.
