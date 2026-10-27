package bypassfast

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Every script-bearing solve (Akamai sensor and SBSD, Kasada sensor and CD,
// Incapsula Reese84 and UTMVC) travels hash-first: the request carries the
// script's SHA-256 as script_id and no script. The API keeps every script it
// has been sent for days, so the body is only needed when nobody has sent
// that script yet; it then answers 409 script_cache_miss (not billed) and the
// SDK repeats the call once with the script. A new script version costs one
// extra round trip, once, fleet-wide.

// scriptExchange describes one script-bearing solve. build renders the wire
// body with or without the script; key identifies the script in the client's
// miss memory; hasScript is false when the caller supplied only a script_id,
// in which case a cache miss is returned to the caller.
type scriptExchange struct {
	path      string
	key       string
	hasScript bool
	// scriptBytes is the encoded size of the script on the wire.
	scriptBytes int
	build       func(withScript bool) any
	limit       int
	timeout     time.Duration
}

// solveScript performs the hash-first exchange and its one-time fallback.
// scriptBytes is the size the script adds to the wire body when it is sent,
// checked up front so a script the API could never accept fails before any
// round trip rather than on the fallback.
func (c *Client) solveScript(ctx context.Context, exchange scriptExchange, response any) (ResponseMeta, error) {
	if exchange.hasScript && exchange.scriptBytes > exchange.limit {
		return ResponseMeta{}, &ValidationError{Field: "script", Message: fmt.Sprintf("encoded script exceeds the %d MiB API limit", exchange.limit/(1024*1024))}
	}
	withScript := exchange.hasScript && c.scripts.recentlyMissed(exchange.key)
	meta, err := c.doJSONWithLimit(ctx, http.MethodPost, exchange.path, exchange.build(withScript), response, exchange.limit, exchange.timeout)
	if err != nil && exchange.hasScript && !withScript && isScriptCacheError(err) {
		c.scripts.markMissed(exchange.key)
		prior := meta.Attempts
		meta, err = c.doJSONWithLimit(ctx, http.MethodPost, exchange.path, exchange.build(true), response, exchange.limit, exchange.timeout)
		applyFallbackAttempts(&meta, err, prior)
		withScript = true
	}
	if err == nil && withScript {
		c.scripts.markRegistered(exchange.key)
	}
	return meta, err
}

// isScriptCacheError reports whether err says the API has no script for the
// script_id it was sent (409 script_cache_miss) or could not look it up (503
// script_cache_unavailable, which the retry policy has already retried).
func isScriptCacheError(err error) bool {
	return IsErrorCode(err, "script_cache_miss") || IsErrorCode(err, "script_cache_unavailable")
}

// ScriptID returns the script_id of a raw challenge script: the lower-case hex
// SHA-256 of its bytes exactly as fetched. The SDK computes it for every
// script it sends; call it to persist an ID beside a cached script.
func ScriptID(rawScript []byte) string {
	return sha256Hex(rawScript)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// normalizeScriptID lower-cases and trims an explicit script_id, reporting
// whether it is a well-formed SHA-256 hex digest. An empty value is valid and
// means none was given.
func normalizeScriptID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", true
	}
	return value, validSHA256(value)
}

// resolveScriptID reconciles an explicit script_id with the script bytes:
// the bytes decide the ID, and an explicit ID that disagrees is a local
// validation error (the API would answer 400 script_id_mismatch).
func resolveScriptID(explicit string, script []byte) (string, error) {
	scriptID, ok := normalizeScriptID(explicit)
	if !ok {
		return "", &ValidationError{Field: "script_id", Message: "must be a 64-character SHA-256 hex digest"}
	}
	if len(script) > 0 {
		computed := sha256Hex(script)
		if scriptID != "" && scriptID != computed {
			return "", &ValidationError{Field: "script_id", Message: "does not match the script bytes"}
		}
		scriptID = computed
	}
	return scriptID, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// base64Len is the length of the standard base64 encoding of n bytes.
func base64Len(n int) int {
	return base64.StdEncoding.EncodedLen(n)
}
