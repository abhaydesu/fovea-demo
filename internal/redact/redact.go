// Package redact masks credentials and PII in captured payloads before they are stored.
package redact

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

const mask = "[redacted]"

var sensitiveHeader = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true,
}

var sensitiveKey = regexp.MustCompile(`(?i)pass(word|wd)?|secret|token|api[_-]?key|authorization|credit|card|cvv|ssn|otp`)

// Headers returns a copy with sensitive header values masked.
func Headers(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeader[strings.ToLower(k)] {
			v = mask
		}
		out[k] = v
	}
	return out
}

// Body masks sensitive keys inside JSON bodies. Non-JSON bodies are returned untouched.
func Body(b string) string {
	trim := strings.TrimSpace(b)
	if len(trim) == 0 || (trim[0] != '{' && trim[0] != '[') {
		return b
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(trim)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return b
	}
	changed := false
	v = walk(v, &changed)
	if !changed {
		return b // keep the original bytes (key order, spacing) when nothing is sensitive
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return string(out) + "\n"
}

func walk(v any, changed *bool) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if sensitiveKey.MatchString(k) {
				x[k] = mask
				*changed = true
			} else {
				x[k] = walk(val, changed)
			}
		}
	case []any:
		for i := range x {
			x[i] = walk(x[i], changed)
		}
	}
	return v
}
