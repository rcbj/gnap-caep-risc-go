// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func B64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func B64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func B64URLDecode(value string) ([]byte, error) {
	if pad := len(value) % 4; pad != 0 {
		value += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(value)
}

func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func Dump(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func DecodeJSON(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func TimingEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func IsNumber(value any) bool {
	switch value.(type) {
	case json.Number, float64, float32, int, int32, int64, uint, uint32, uint64:
		return true
	default:
		return false
	}
}

func AsFloat(value any) (float64, bool) {
	switch n := value.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

func AsMap(value any) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	return m, ok
}

func AsList(value any) ([]any, bool) {
	l, ok := value.([]any)
	return l, ok
}

func AsString(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok
}

func str(value any) string {
	s, _ := value.(string)
	return s
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
