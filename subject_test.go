// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import "testing"

func subjectCheck() IDCheck {
	return IDCheck{Issuer: "https://as.example", Audiences: []string{}, Skew: 0, Keys: func() ([]map[string]any, error) {
		return []map[string]any{}, nil
	}}
}

func TestUIDFromAccountKeepsTheProtocolSubject(t *testing.T) {
	person, err := PersonFrom(map[string]any{
		"sub_ids": []any{
			map[string]any{"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"},
			map[string]any{"format": "account", "uri": "acct:gnap-demo-user@localhost:8081"},
		},
	}, subjectCheck())
	if err != nil {
		t.Fatal(err)
	}
	if person.Sub != "urn:uuid:abc" || person.Iss != "https://as.example" || person.Uid == nil || *person.Uid != "gnap-demo-user" {
		t.Fatalf("%#v", person)
	}
}

func TestPercentDecodesTheUserPartAndKeepsInvalidEncoding(t *testing.T) {
	decoded, err := PersonFrom(map[string]any{
		"sub_ids": []any{map[string]any{"format": "account", "uri": "acct:ada%20lovelace@idp.example"}},
	}, subjectCheck())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sub != "acct:ada%20lovelace@idp.example" || decoded.Uid == nil || *decoded.Uid != "ada lovelace" {
		t.Fatalf("%#v uid %v", decoded, decoded.Uid)
	}
	kept, err := PersonFrom(map[string]any{
		"sub_ids": []any{map[string]any{"format": "account", "uri": "acct:%E0%A4%A@idp.example"}},
	}, subjectCheck())
	if err != nil {
		t.Fatal(err)
	}
	if kept.Uid == nil || *kept.Uid != "%E0%A4%A" {
		t.Fatalf("uid %v", kept.Uid)
	}
}

func TestUIDStaysUnsetWithoutAnAccountIdentifier(t *testing.T) {
	person, err := PersonFrom(map[string]any{
		"sub_ids": []any{map[string]any{"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"}},
	}, subjectCheck())
	if err != nil {
		t.Fatal(err)
	}
	if person.Uid != nil || person.Sub != "urn:uuid:abc" {
		t.Fatalf("%#v", person)
	}
}
