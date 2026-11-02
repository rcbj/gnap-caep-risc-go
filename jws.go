// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"bytes"
	"encoding/json"
	"strings"
)

// JWS is a verified compact JWS header and payload.
type JWS struct {
	Header  map[string]any
	Payload map[string]any
}

var jwsAlgs = []struct{ alg, kty string }{
	{"RS256", "RSA"}, {"RS384", "RSA"}, {"RS512", "RSA"},
	{"PS256", "RSA"}, {"PS384", "RSA"}, {"PS512", "RSA"},
	{"ES256", "EC"}, {"ES384", "EC"}, {"ES512", "EC"},
	{"EdDSA", "OKP"}, {"Ed25519", "OKP"},
}

func supportedJWS() string {
	names := make([]string, len(jwsAlgs))
	for i, item := range jwsAlgs {
		names[i] = item.alg
	}
	return strings.Join(names, ", ")
}

func algSpec(alg string) (string, bool) {
	for _, item := range jwsAlgs {
		if item.alg == alg {
			return item.kty, true
		}
	}
	return "", false
}

func decodeObject(raw []byte, what string) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, failCause("signature", "the token's header or payload is not JSON", err)
	}
	doc, ok := AsMap(value)
	if !ok {
		return nil, fail("signature", "the token's "+what+" is not a JSON object")
	}
	return doc, nil
}

// VerifyCompactJWS checks a Security Event Token or an ID token. none and HMAC are refused.
func VerifyCompactJWS(token string, keys []map[string]any) (*JWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fail("signature", "the token is not a compact JWS")
	}
	headerRaw, err := b64urlStrict(parts[0], "header")
	if err != nil {
		return nil, err
	}
	payloadRaw, err := b64urlStrict(parts[1], "payload")
	if err != nil {
		return nil, err
	}
	header, err := decodeObject(headerRaw, "header")
	if err != nil {
		return nil, err
	}
	payload, err := decodeObject(payloadRaw, "payload")
	if err != nil {
		return nil, err
	}
	alg := str(header["alg"])
	kty, ok := algSpec(alg)
	if !ok {
		shown := alg
		if shown == "" {
			shown = "(no alg)"
		}
		return nil, fail("signature", "the token is signed with "+shown+", which this client does not verify ("+supportedJWS()+")")
	}
	if _, crit := header["crit"]; crit {
		return nil, fail("signature", "the token's header has a crit member this client does not understand")
	}
	kid := ""
	if text, ok := header["kid"].(string); ok {
		kid = text
	}
	var candidates []map[string]any
	for _, key := range keys {
		if kid != "" && str(key["kid"]) != kid {
			continue
		}
		if str(key["kty"]) != kty {
			continue
		}
		if use := str(key["use"]); use != "" && use != "sig" {
			continue
		}
		if keyAlg := str(key["alg"]); keyAlg != "" && keyAlg != alg {
			continue
		}
		candidates = append(candidates, key)
	}
	if len(candidates) == 0 {
		suffix := ""
		if kid != "" {
			suffix = " with kid " + kid
		}
		return nil, fail("signature", "no "+kty+" signing key"+suffix+" was published")
	}
	signature, err := b64urlStrict(parts[2], "signature")
	if err != nil {
		return nil, err
	}
	data := parts[0] + "." + parts[1]
	for _, jwk := range candidates {
		public, err := PublicKeyFromJWK(jwk)
		if err != nil {
			continue
		}
		if VerifyRaw(public, alg, []byte(data), signature) {
			return &JWS{Header: header, Payload: payload}, nil
		}
	}
	return nil, fail("signature", "the token's signature does not verify against the published keys")
}
