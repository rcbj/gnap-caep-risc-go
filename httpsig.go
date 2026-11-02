// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

func ContentDigest(body string) string {
	return "sha-256=:" + B64Std(SHA256([]byte(body))) + ":"
}

func sfString(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func signatureParams(components []string, created int64, nonce, keyid string) string {
	quoted := make([]string, len(components))
	for i, name := range components {
		quoted[i] = `"` + name + `"`
	}
	return fmt.Sprintf(`(%s);created=%d;nonce=%s;keyid=%s;tag="gnap"`, strings.Join(quoted, " "), created, sfString(nonce), sfString(keyid))
}

func signatureBase(components []string, method, href string, headers map[string]string, serialised string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		var value string
		switch component {
		case "@method":
			value = strings.ToUpper(method)
		case "@target-uri":
			value = href
		default:
			raw, ok := headers[component]
			if !ok {
				return "", fmt.Errorf("Cannot sign %q: the request has no such header", component)
			}
			value = strings.TrimSpace(raw)
		}
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("Cannot sign %q: the value contains a line break", component)
		}
		lines = append(lines, `"`+component+`": `+value)
	}
	lines = append(lines, `"@signature-params": `+serialised)
	return strings.Join(lines, "\n"), nil
}

func SignRequest(key *ClientKey, method, rawURL string, headers map[string]string, body *string) (map[string]string, error) {
	href := rawURL
	if absolute, err := Href(rawURL); err == nil {
		href = absolute
	}
	lower := map[string]string{}
	for name, value := range headers {
		lower[strings.ToLower(name)] = value
	}
	components := []string{"@method", "@target-uri"}
	added := map[string]string{}
	if body != nil && len(*body) > 0 {
		added["content-digest"] = ContentDigest(*body)
		lower["content-digest"] = added["content-digest"]
		components = append(components, "content-digest")
	}
	if _, ok := lower["authorization"]; ok {
		components = append(components, "authorization")
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	params := signatureParams(components, time.Now().Unix(), B64URL(buf), key.Kid)
	base, err := signatureBase(components, method, href, lower, params)
	if err != nil {
		return nil, err
	}
	signature, err := SignRaw(key, []byte(base))
	if err != nil {
		return nil, err
	}
	added["signature-input"] = "sig1=" + params
	added["signature"] = "sig1=:" + B64Std(signature) + ":"
	return added, nil
}
