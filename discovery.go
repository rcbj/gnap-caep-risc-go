// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"strconv"
	"strings"
)

// GrantServer is the metadata from OPTIONS on the grant endpoint.
type GrantServer struct {
	GrantRequestEndpoint string
	InteractionStart     []string
	InteractionFinish    []string
	KeyProofs            []string
	SubIDFormats         []string
	AssertionFormats     []string
}

// OpenID is the issuer and its jwks_uri.
type OpenID struct {
	Issuer  string
	JWKSURI string
}

func stringList(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	list, ok := AsList(value)
	if !ok {
		return nil, fail("discovery", "a grant-server metadata list is not an array of strings")
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, fail("discovery", "a grant-server metadata list is not an array of strings")
		}
		out = append(out, text)
	}
	return out, nil
}

func ValidateGrantServer(raw any, grantEndpoint string) (*GrantServer, error) {
	doc, ok := AsMap(raw)
	if !ok {
		return nil, fail("discovery", "grant-server metadata must be a JSON object")
	}
	endpoint := str(doc["grant_request_endpoint"])
	if endpoint == "" {
		return nil, fail("discovery", "grant-server metadata has no grant_request_endpoint")
	}
	advertised, err := Href(endpoint)
	if err != nil {
		return nil, fail("discovery", "grant-server metadata has no grant_request_endpoint")
	}
	asked, err := Href(grantEndpoint)
	if err != nil {
		return nil, err
	}
	if strings.TrimRight(advertised, "/") != strings.TrimRight(asked, "/") {
		return nil, fmtFail("discovery", "the grant server says its endpoint is %s, not %s", endpoint, grantEndpoint)
	}
	meta := &GrantServer{GrantRequestEndpoint: endpoint}
	if meta.InteractionStart, err = stringList(doc["interaction_start_modes_supported"]); err != nil {
		return nil, err
	}
	if meta.InteractionFinish, err = stringList(doc["interaction_finish_methods_supported"]); err != nil {
		return nil, err
	}
	if meta.KeyProofs, err = stringList(doc["key_proofs_supported"]); err != nil {
		return nil, err
	}
	if meta.SubIDFormats, err = stringList(doc["sub_id_formats_supported"]); err != nil {
		return nil, err
	}
	if meta.AssertionFormats, err = stringList(doc["assertion_formats_supported"]); err != nil {
		return nil, err
	}
	return meta, nil
}

func DiscoverGrantServer(grantEndpoint string, tlsOpt TLSOpt) (*GrantServer, error) {
	answer, err := Send(grantEndpoint, "OPTIONS", map[string]string{"accept": "application/json"}, nil, tlsOpt, "discovery")
	if err != nil {
		return nil, err
	}
	parsed, err := DecodeJSON(answer.Body)
	if err != nil {
		return nil, failCause("discovery", grantEndpoint+" did not answer JSON grant-server metadata ("+strconv.Itoa(answer.Status)+")", err)
	}
	if answer.Status != 200 {
		return nil, fmtFail("discovery", "%s answered %d for discovery", grantEndpoint, answer.Status)
	}
	return ValidateGrantServer(parsed, grantEndpoint)
}

func DiscoverOpenID(issuer string, tlsOpt TLSOpt) (*OpenID, error) {
	urls, err := WellKnown(issuer, "openid-configuration")
	if err != nil {
		return nil, err
	}
	last := fmtFail("discovery", "no OpenID Provider metadata at %s", strings.Join(urls, " or "))
	for i, one := range urls {
		answer, err := Send(one, "GET", map[string]string{"accept": "application/json"}, nil, tlsOpt, "discovery")
		if err != nil {
			return nil, err
		}
		if answer.Status == 404 && i != len(urls)-1 {
			continue
		}
		parsed, jerr := DecodeJSON(answer.Body)
		doc, ok := AsMap(parsed)
		if jerr != nil || answer.Status != 200 || !ok || str(doc["jwks_uri"]) == "" {
			last = fmtFail("discovery", "%s answered %d without OpenID Provider metadata", one, answer.Status)
			continue
		}
		got := str(doc["issuer"])
		if got != "" && strings.TrimRight(got, "/") != strings.TrimRight(issuer, "/") {
			return nil, fmtFail("discovery", "%s says its issuer is %s, not %s", one, got, issuer)
		}
		if got == "" {
			got = issuer
		}
		return &OpenID{Issuer: got, JWKSURI: str(doc["jwks_uri"])}, nil
	}
	return nil, last
}
