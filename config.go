// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"os"
	"path/filepath"
	"strings"
)

// Display is the client name and URI shown to the resource owner.
type Display struct {
	Name string
	URI  string
}

// SSFConfig is the transmitter the receiver polls. It is absent when signals are off.
type SSFConfig struct {
	Transmitter    string
	PollIntervalMs int
}

// Config is a resolved gnap.json. Signals is nil when CAEP and RISC stay on, and false when they are off.
type Config struct {
	GrantEndpoint      string
	IDTokenIssuer      string
	Application        string
	ClassID            string
	Display            *Display
	Access             []any
	Signals            *bool
	SubIDFormats       []string
	AssertionFormats   []string
	Key                *ClientKey
	FinishURI          string
	FinishMethod       string
	InteractionStart   []string
	HashMethod         string
	RequireBoundTokens bool
	UseInstanceID      bool
	TLSCA              string
	AllowInsecure      bool
	ClockToleranceSec  float64
	MaxWaitSec         float64
	TransactionTTLSec  float64
	SSF                *SSFConfig
}

func boolPtr(v bool) *bool { return &v }

func asBool(value any) (bool, bool) {
	b, ok := value.(bool)
	return b, ok
}

func readPath(path, base, what string) (string, error) {
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(base, path)
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return "", failCause("config", "could not read "+what+" at "+full+": "+err.Error(), err)
	}
	return string(raw), nil
}

func secret(raw, base, what string) (string, error) {
	if strings.HasPrefix(raw, "env:") {
		name := raw[4:]
		value := os.Getenv(name)
		if value == "" {
			return "", fail("config", what+" reads "+name+", and that variable is empty")
		}
		return value, nil
	}
	if strings.HasPrefix(raw, "file:") {
		return readPath(raw[5:], base, what)
	}
	return raw, nil
}

func keyValue(raw, base, what string) (string, error) {
	if strings.HasPrefix(raw, "env:") || strings.HasPrefix(raw, "file:") || strings.Contains(raw, "-----BEGIN") {
		return secret(raw, base, what)
	}
	return readPath(raw, base, what)
}

// ReadTrust returns PEM trust material. A missing file is empty, not an error.
func ReadTrust(raw, base string) string {
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "-----BEGIN") {
		return raw
	}
	if strings.HasPrefix(raw, "env:") {
		return os.Getenv(raw[4:])
	}
	path := raw
	if strings.HasPrefix(raw, "file:") {
		path = raw[5:]
	}
	if path == "" {
		return ""
	}
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(base, path)
	}
	text, err := os.ReadFile(full)
	if err != nil {
		return ""
	}
	return string(text)
}

func ssfRight(right any) bool {
	switch value := right.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		return trimmed == "ssf.read" || trimmed == "ssf.manage"
	case map[string]any:
		kind, _ := value["type"].(string)
		return kind == "ssf.read" || kind == "ssf.manage"
	default:
		return false
	}
}

func checkURL(value, name string, allowHTTP bool) (string, error) {
	href, err := Href(value)
	if err != nil {
		return "", fail("config", name+" is not a URL: "+value)
	}
	scheme := strings.SplitN(href, ":", 2)[0]
	if scheme == "https" || (scheme == "http" && allowHTTP) {
		return href, nil
	}
	extra := ""
	if !allowHTTP {
		extra = ", or http on loopback"
	}
	return "", fail("config", name+" must use https"+extra+": "+value)
}

func stringListOr(value any, fallback []string) []string {
	list, ok := AsList(value)
	if !ok || value == nil {
		out := make([]string, len(fallback))
		copy(out, fallback)
		return out
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, str(item))
	}
	return out
}

func numberOr(doc map[string]any, key string, fallback float64) float64 {
	if _, ok := doc[key]; !ok || doc[key] == nil {
		return fallback
	}
	n, ok := AsFloat(doc[key])
	if !ok {
		return fallback
	}
	return n
}

func truthy(value any) bool {
	if value == nil {
		return false
	}
	if b, ok := value.(bool); ok {
		return b
	}
	if s, ok := value.(string); ok {
		return s != ""
	}
	if n, ok := AsFloat(value); ok {
		return n != 0
	}
	return true
}

// Resolve checks raw gnap.json and returns the configuration the client uses.
func Resolve(raw map[string]any, baseDir string) (*Config, error) {
	if raw == nil {
		return nil, fail("config", "the configuration must be a JSON object")
	}
	if _, present := raw["signals"]; present {
		if _, ok := asBool(raw["signals"]); !ok {
			return nil, fail("config", "signals must be true or false")
		}
	}
	signalsOff := false
	if value, ok := asBool(raw["signals"]); ok && !value {
		signalsOff = true
	}
	application := strings.TrimSpace(str(raw["application"]))
	if application == "" {
		return nil, fail("config", "application is required: the registered GNAP client")
	}
	grantRaw := strings.TrimSpace(str(raw["grantEndpoint"]))
	if grantRaw == "" {
		return nil, fail("config", "grantEndpoint is required")
	}
	allowInsecure, _ := asBool(raw["allowInsecure"])
	allowInsecure = raw["allowInsecure"] == true
	grantEndpoint, err := checkURL(grantRaw, "grantEndpoint", allowInsecure)
	if err != nil {
		return nil, err
	}
	origin, err := Origin(grantEndpoint)
	if err != nil {
		return nil, err
	}
	idTokenIssuer := strings.TrimRight(strings.TrimSpace(str(raw["idTokenIssuer"])), "/")
	if idTokenIssuer == "" {
		idTokenIssuer = strings.TrimRight(origin, "/")
	}
	if !strings.HasPrefix(idTokenIssuer, "https://") && !strings.HasPrefix(idTokenIssuer, "http://") {
		return nil, fail("config", "idTokenIssuer must be an http(s) URL")
	}
	proofRaw := strings.TrimSpace(str(raw["keyProof"]))
	if proofRaw != "" && !containsString(proofs, proofRaw) {
		return nil, fail("config", "keyProof must be "+strings.Join(proofs, ", ")+", not "+proofRaw)
	}
	if str(raw["privateKey"]) == "" {
		return nil, fail("config", "privateKey is required")
	}
	privateKey, err := keyValue(str(raw["privateKey"]), baseDir, "the private key")
	if err != nil {
		return nil, err
	}
	var certificate string
	if str(raw["certificate"]) != "" {
		certificate, err = keyValue(str(raw["certificate"]), baseDir, "the certificate")
		if err != nil {
			return nil, err
		}
	}
	key, err := LoadClientKey(privateKey, certificate, proofRaw)
	if err != nil {
		return nil, err
	}
	if key.Proof == "mtls" {
		parsed, perr := parseAbsolute(grantEndpoint)
		if perr != nil || parsed.Scheme != "https" {
			return nil, fail("config", "mutual TLS needs an https grant endpoint")
		}
	}
	finishMethod := str(raw["finishMethod"])
	if finishMethod == "" {
		finishMethod = "redirect"
	}
	if finishMethod != "redirect" && finishMethod != "push" {
		return nil, fail("config", "finishMethod must be redirect or push")
	}
	finishRaw := strings.TrimSpace(str(raw["finishUri"]))
	finishURI := ""
	if finishRaw != "" {
		finishURI, err = checkURL(finishRaw, "finishUri", allowInsecure || IsLoopback(finishRaw))
		if err != nil {
			return nil, err
		}
	}
	hashMethod := str(raw["hashMethod"])
	if hashMethod == "" {
		hashMethod = "sha-256"
	}
	if hashMethod != "sha-256" {
		return nil, fail("config", "hashMethod must be sha-256")
	}
	var interaction []string
	if _, ok := raw["interactionStart"]; !ok || raw["interactionStart"] == nil {
		interaction = []string{"redirect"}
	} else {
		list, ok := AsList(raw["interactionStart"])
		if !ok || len(list) == 0 {
			return nil, fail("config", "interactionStart must name at least one mode")
		}
		interaction = make([]string, 0, len(list))
		for _, item := range list {
			text := str(item)
			if text == "" {
				return nil, fail("config", "interactionStart must name at least one mode")
			}
			interaction = append(interaction, text)
		}
	}
	var requested []any
	if _, ok := raw["access"]; !ok || raw["access"] == nil {
		requested = []any{"ssf.read", "ssf.manage"}
	} else {
		list, ok := AsList(raw["access"])
		if !ok {
			return nil, fail("config", "access must list at least one right")
		}
		requested = list
	}
	access := requested
	if signalsOff {
		access = nil
		for _, right := range requested {
			if !ssfRight(right) {
				access = append(access, right)
			}
		}
	} else {
		access = append([]any{}, requested...)
	}
	if len(access) == 0 {
		if signalsOff {
			return nil, fail("config", "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller must name a right this authorization server grants")
		}
		return nil, fail("config", "access must list at least one right")
	}
	tlsCA := ""
	if raw["tlsCa"] != nil {
		tlsCA = ReadTrust(str(raw["tlsCa"]), baseDir)
	}
	var ssf *SSFConfig
	if !signalsOff {
		rawSSF, _ := AsMap(raw["ssf"])
		transmitter := ""
		if rawSSF != nil {
			transmitter = str(rawSSF["transmitter"])
		}
		if transmitter == "" {
			transmitter = str(raw["transmitterIssuer"])
		}
		transmitter = strings.TrimRight(transmitter, "/")
		if transmitter != "" {
			if !strings.HasPrefix(transmitter, "https://") && !strings.HasPrefix(transmitter, "http://") {
				return nil, fail("config", "ssf.transmitter must be an http(s) URL")
			}
			ssf = &SSFConfig{Transmitter: transmitter}
			if rawSSF != nil && truthy(rawSSF["pollIntervalMs"]) {
				if n, ok := AsFloat(rawSSF["pollIntervalMs"]); ok {
					ssf.PollIntervalMs = int(n)
				}
			}
		}
	}
	var display *Display
	if displayIn, ok := AsMap(raw["display"]); ok {
		name := str(displayIn["name"])
		uri := str(displayIn["uri"])
		if name != "" || uri != "" {
			display = &Display{Name: name, URI: uri}
		}
	}
	cfg := &Config{
		GrantEndpoint:      grantEndpoint,
		IDTokenIssuer:      idTokenIssuer,
		Application:        application,
		Display:            display,
		Access:             access,
		SubIDFormats:       stringListOr(raw["subIdFormats"], []string{"iss_sub", "account", "opaque"}),
		AssertionFormats:   stringListOr(raw["assertionFormats"], []string{"id_token"}),
		Key:                key,
		FinishURI:          finishURI,
		FinishMethod:       finishMethod,
		InteractionStart:   interaction,
		HashMethod:         "sha-256",
		RequireBoundTokens: raw["requireBoundTokens"] != false,
		UseInstanceID:      raw["useInstanceId"] != false,
		TLSCA:              tlsCA,
		AllowInsecure:      allowInsecure,
		ClockToleranceSec:  numberOr(raw, "clockToleranceSec", 30),
		MaxWaitSec:         numberOr(raw, "maxWaitSec", 30),
		TransactionTTLSec:  numberOr(raw, "transactionTtlSec", 600),
		SSF:                ssf,
	}
	if classID := str(raw["classId"]); classID != "" {
		cfg.ClassID = classID
	}
	if signalsOff {
		cfg.Signals = boolPtr(false)
	}
	return cfg, nil
}

// ReadConfigFile loads gnap.json from path.
func ReadConfigFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, failCause("config", "could not read "+path+": "+err.Error(), err)
	}
	parsed, err := DecodeJSON(string(raw))
	if err != nil {
		return nil, failCause("config", "could not read "+path+": "+err.Error(), err)
	}
	doc, ok := AsMap(parsed)
	if !ok {
		return nil, fail("config", "the configuration must be a JSON object")
	}
	abs, err := filepath.Abs(path)
	base := "."
	if err == nil {
		base = filepath.Dir(abs)
	}
	return Resolve(doc, base)
}
