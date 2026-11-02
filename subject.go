// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Person is the subject of a grant. Uid is nil when the grant has no account identifier.
type Person struct {
	Sub               string
	Claims            map[string]any
	AssertionVerified bool
	Iss               string
	Uid               *string
	Email             string
	Name              string
	PreferredUsername string
	Sid               string
	Acr               string
	Amr               []string
}

// IDCheck is how an id_token is judged.
type IDCheck struct {
	Issuer    string
	Audiences []string
	Skew      float64
	Keys      func() ([]map[string]any, error)
}

var acctRE = regexp.MustCompile(`^acct:([^@]+)@(.+)$`)

func uidPtr(value string) *string { return &value }

func decodeURIComponent(value string) (string, error) {
	out := make([]byte, 0, len(value))
	for index := 0; index < len(value); {
		if value[index] != '%' {
			r, size := utf8.DecodeRuneInString(value[index:])
			if r == utf8.RuneError && size == 1 {
				out = append(out, value[index])
				index++
				continue
			}
			out = append(out, value[index:index+size]...)
			index += size
			continue
		}
		if index+3 > len(value) {
			return "", fail("validation", "bad percent-encoding")
		}
		hexpart := value[index+1 : index+3]
		n, err := strconv.ParseUint(hexpart, 16, 8)
		if err != nil || len(hexpart) < 2 {
			return "", fail("validation", "bad percent-encoding")
		}
		out = append(out, byte(n))
		index += 3
	}
	if !utf8.Valid(out) {
		return "", fail("validation", "bad percent-encoding")
	}
	return string(out), nil
}

// UIDFromAccount returns the user part of an acct: URI. Invalid percent-encoding is kept as written.
func UIDFromAccount(uri string) *string {
	match := acctRE.FindStringSubmatch(uri)
	if match == nil {
		return nil
	}
	decoded, err := decodeURIComponent(match[1])
	if err != nil {
		return uidPtr(match[1])
	}
	return uidPtr(decoded)
}

func stringItems(value any) []string {
	switch item := value.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(item))
		for _, one := range item {
			out = append(out, toString(one))
		}
		return out
	case string:
		return []string{item}
	default:
		return []string{toString(value)}
	}
}

func toString(value any) string {
	switch item := value.(type) {
	case string:
		return item
	case nil:
		return ""
	default:
		text, err := Dump(value)
		if err != nil {
			return ""
		}
		return text
	}
}

func findSub(list []any, format, field string) map[string]any {
	for _, item := range list {
		doc, ok := AsMap(item)
		if !ok || str(doc["format"]) != format {
			continue
		}
		if _, ok := doc[field].(string); ok {
			return doc
		}
	}
	return nil
}

// PersonFrom reads a GNAP subject. An id_token is checked when one is present.
func PersonFrom(subject any, check IDCheck) (*Person, error) {
	doc, ok := AsMap(subject)
	if !ok {
		return nil, nil
	}
	subIDs, _ := AsList(doc["sub_ids"])
	issSub := findSub(subIDs, "iss_sub", "sub")
	opaque := findSub(subIDs, "opaque", "id")
	account := findSub(subIDs, "account", "uri")
	assertions, _ := AsList(doc["assertions"])
	var idToken map[string]any
	for _, item := range assertions {
		one, ok := AsMap(item)
		if ok && str(one["format"]) == "id_token" {
			if _, isStr := one["value"].(string); isStr {
				idToken = one
				break
			}
		}
	}
	claims := map[string]any{}
	sub := ""
	iss := ""
	if issSub != nil {
		sub = str(issSub["sub"])
		if text, ok := issSub["iss"].(string); ok {
			iss = text
		}
	}
	verified := false
	if idToken != nil {
		if check.Keys == nil {
			return nil, fail("validation", "subject key lookup must be synchronous")
		}
		keys, err := check.Keys()
		if err != nil {
			return nil, err
		}
		verifiedJWS, err := VerifyCompactJWS(str(idToken["value"]), keys)
		if err != nil {
			return nil, err
		}
		payload := verifiedJWS.Payload
		if str(payload["iss"]) != check.Issuer {
			return nil, fmtFail("validation", "the id_token was issued by %s, not %s", toString(payload["iss"]), check.Issuer)
		}
		tokenSub := str(payload["sub"])
		if tokenSub == "" {
			return nil, fail("validation", "the id_token has no sub")
		}
		exp, expOK := AsFloat(payload["exp"])
		if !expOK {
			return nil, fail("validation", "the id_token has no exp")
		}
		now := float64(time.Now().Unix())
		if exp+check.Skew < now {
			return nil, fail("validation", "the id_token has expired")
		}
		if nbf, ok := AsFloat(payload["nbf"]); ok && nbf-check.Skew > now {
			return nil, fail("validation", "the id_token is not valid yet")
		}
		if iat, ok := AsFloat(payload["iat"]); ok && iat-check.Skew > now {
			return nil, fail("validation", "the id_token is issued in the future")
		}
		aud := stringItems(payload["aud"])
		var known []string
		for _, item := range check.Audiences {
			if item != "" {
				known = append(known, item)
			}
		}
		if len(known) > 0 {
			match := false
			for _, one := range aud {
				if containsString(known, one) {
					match = true
					break
				}
			}
			if !match {
				shown := "(no audience)"
				if len(aud) > 0 {
					shown = strings.Join(aud, ", ")
				}
				return nil, fail("validation", "the id_token is for "+shown+", not "+strings.Join(known, " or "))
			}
		}
		if sub != "" && tokenSub != sub {
			return nil, fail("validation", "the id_token is about somebody other than the subject identifier")
		}
		sub = tokenSub
		iss = str(payload["iss"])
		for key, value := range payload {
			claims[key] = value
		}
		verified = true
	}
	if sub == "" && opaque != nil {
		sub = str(opaque["id"])
	}
	if sub == "" && account != nil {
		sub = str(account["uri"])
	}
	if sub == "" {
		return nil, nil
	}
	var uid *string
	if account != nil {
		uid = UIDFromAccount(str(account["uri"]))
	}
	person := &Person{Sub: sub, Claims: claims, AssertionVerified: verified, Iss: iss, Uid: uid}
	if email, ok := claims["email"].(string); ok {
		person.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		person.Name = name
	}
	if preferred, ok := claims["preferred_username"].(string); ok {
		person.PreferredUsername = preferred
	}
	if sid, ok := claims["sid"].(string); ok {
		person.Sid = sid
	} else if sid, ok := claims["session_id"].(string); ok {
		person.Sid = sid
	}
	if acr, ok := claims["acr"].(string); ok {
		person.Acr = acr
	}
	if amr, ok := AsList(claims["amr"]); ok {
		person.Amr = make([]string, 0, len(amr))
		for _, item := range amr {
			person.Amr = append(person.Amr, toString(item))
		}
	}
	return person, nil
}
