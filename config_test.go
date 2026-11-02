// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
)

func testKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func resolveTest(t *testing.T, extra map[string]any) *Config {
	t.Helper()
	body := map[string]any{
		"grantEndpoint": "https://idp.example/gnap",
		"application":   "app",
		"privateKey":    testKey(t),
		"keyProof":      "httpsig",
	}
	for key, value := range extra {
		body[key] = value
	}
	cfg, err := Resolve(body, ".")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDefaultsAccessAndFillsTransmitter(t *testing.T) {
	resolved := resolveTest(t, map[string]any{"transmitterIssuer": "https://idp.example/issuer/"})
	if !reflect.DeepEqual(resolved.Access, []any{"ssf.read", "ssf.manage"}) {
		t.Fatalf("access %#v", resolved.Access)
	}
	if resolved.SSF == nil || resolved.SSF.Transmitter != "https://idp.example/issuer" {
		t.Fatalf("ssf %#v", resolved.SSF)
	}
	if resolved.Signals != nil {
		t.Fatal("signals should be omitted")
	}
	on := resolveTest(t, map[string]any{"signals": true, "transmitterIssuer": "https://idp.example/issuer"})
	if on.Signals != nil || on.SSF == nil {
		t.Fatalf("signals on: signals %#v ssf %#v", on.Signals, on.SSF)
	}
}

func TestDropsSSFRightsAndTransmitterWhenSignalsIsFalse(t *testing.T) {
	resolved := resolveTest(t, map[string]any{
		"signals":           false,
		"access":            []any{"openid", "ssf.read"},
		"transmitterIssuer": "https://idp.example",
		"ssf":               map[string]any{"transmitter": "https://idp.example/tx", "pollIntervalMs": 3000},
	})
	if !reflect.DeepEqual(resolved.Access, []any{"openid"}) {
		t.Fatalf("access %#v", resolved.Access)
	}
	if resolved.SSF != nil {
		t.Fatal("ssf should be omitted")
	}
	if resolved.Signals == nil || *resolved.Signals {
		t.Fatalf("signals %#v", resolved.Signals)
	}
	kept := resolveTest(t, map[string]any{
		"signals": false,
		"access": []any{
			"openid",
			" ssf.read ",
			map[string]any{"type": "ssf.manage", "actions": []any{"read"}},
			map[string]any{"type": "api"},
			map[string]any{"type": " ssf.read "},
		},
		"ssf": map[string]any{"transmitter": "not a url"},
	})
	want := []any{"openid", map[string]any{"type": "api"}, map[string]any{"type": " ssf.read "}}
	if !reflect.DeepEqual(kept.Access, want) {
		t.Fatalf("access %#v", kept.Access)
	}
	if kept.SSF != nil {
		t.Fatal("ssf should be omitted")
	}
}

func TestRefusesSignalsOffWhenSSFRightsWereTheOnlyOnes(t *testing.T) {
	message := "signals is false and access has no rights left after ssf.read and ssf.manage were removed"
	check := func(extra map[string]any) {
		t.Helper()
		body := map[string]any{
			"grantEndpoint": "https://idp.example/gnap",
			"application":   "app",
			"privateKey":    testKey(t),
			"keyProof":      "httpsig",
		}
		for key, value := range extra {
			body[key] = value
		}
		_, err := Resolve(body, ".")
		if err == nil || err.Error() == "" || !contains(err.Error(), message) {
			t.Fatalf("error %v", err)
		}
		ge, ok := err.(*Error)
		if !ok || ge.Code != "config" {
			t.Fatalf("code %v", err)
		}
		if !contains(err.Error(), "must name a right this authorization server grants") {
			t.Fatal(err)
		}
	}
	check(map[string]any{"signals": false, "access": []any{"ssf.read", "ssf.manage"}})
	check(map[string]any{"signals": false, "transmitterIssuer": "https://idp.example"})
	check(map[string]any{"signals": false, "access": []any{map[string]any{"type": "ssf.read"}, map[string]any{"type": "ssf.manage"}}})
}

func TestRefusesASignalsValueThatIsNotTrueOrFalse(t *testing.T) {
	body := map[string]any{
		"grantEndpoint": "https://idp.example/gnap",
		"application":   "app",
		"privateKey":    testKey(t),
		"keyProof":      "httpsig",
		"signals":       "no",
	}
	_, err := Resolve(body, ".")
	if err == nil {
		t.Fatal("expected an error")
	}
	ge, ok := err.(*Error)
	if !ok || ge.Code != "config" || err.Error() != "signals must be true or false" {
		t.Fatalf("%v", err)
	}
}

func contains(text, part string) bool {
	return len(part) == 0 || (len(text) >= len(part) && (text == part || len(text) > 0 && stringIndex(text, part) >= 0))
}

func stringIndex(text, part string) int {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
