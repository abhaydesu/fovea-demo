package redact

import (
	"strings"
	"testing"
)

func TestBodyNestedAndArrays(t *testing.T) {
	out := Body(`{"user":"bob","auth":{"api_key":"k","list":[{"Password":"p"}]},"qty":5,"big":12345678901234567890}`)
	for _, leak := range []string{`"k"`, `"p"`} {
		if strings.Contains(out, leak) {
			t.Fatalf("leak %s in %s", leak, out)
		}
	}
	if !strings.Contains(out, `"qty":5`) || !strings.Contains(out, "12345678901234567890") || !strings.Contains(out, "bob") {
		t.Fatalf("non-sensitive data was damaged: %s", out)
	}
}

func TestBodyNonJSONUntouched(t *testing.T) {
	if Body("plain text password=1") != "plain text password=1" {
		t.Fatal("non-JSON must pass through")
	}
}

func TestHeaders(t *testing.T) {
	h := Headers(map[string]string{"Cookie": "s=1", "Content-Type": "x"})
	if h["Cookie"] != "[redacted]" || h["Content-Type"] != "x" {
		t.Fatal(h)
	}
}

func TestBodyUnchangedWhenNothingSensitive(t *testing.T) {
	in := `{"qty":1, "item":"gadget"}`
	if Body(in) != in {
		t.Fatalf("body must be byte-identical, got %q", Body(in))
	}
}
