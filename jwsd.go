// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"strings"
	"time"
)

func athOf(token string) string {
	return B64URL(SHA256([]byte(token)))
}

func DetachedJWS(key *ClientKey, method, rawURL string, body *string, token string) (string, error) {
	href := rawURL
	if absolute, err := Href(rawURL); err == nil {
		href = absolute
	}
	header := map[string]any{
		"alg":     key.Alg,
		"created": time.Now().Unix(),
		"htm":     strings.ToUpper(method),
		"kid":     key.Kid,
		"typ":     "gnap-binding-jwsd",
		"uri":     href,
	}
	if token != "" {
		header["ath"] = athOf(token)
	}
	encodedJSON, err := Dump(header)
	if err != nil {
		return "", err
	}
	encoded := B64URL([]byte(encodedJSON))
	payload := ""
	if body != nil && *body != "" {
		payload = B64URL(SHA256([]byte(*body)))
	}
	signature, err := SignRaw(key, []byte(encoded+"."+payload))
	if err != nil {
		return "", err
	}
	return encoded + "." + payload + "." + B64URL(signature), nil
}
