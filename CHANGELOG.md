# Changelog

All notable changes to the Bypass Fast Go SDK are recorded here. The module
follows [Semantic Versioning](https://semver.org/).

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
