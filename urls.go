// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"net/url"
	"strings"
)

func parseAbsolute(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fail("validation", raw+" is not a URL")
	}
	return u, nil
}

func hostport(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == "" || (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		return host
	}
	return host + ":" + port
}

func Origin(raw string) (string, error) {
	u, err := parseAbsolute(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + hostport(u), nil
}

func Href(raw string) (string, error) {
	u, err := parseAbsolute(raw)
	if err != nil {
		return "", err
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := u.Scheme + "://" + hostport(u) + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

func IsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func WellKnown(issuer, suffix string) ([]string, error) {
	u, err := parseAbsolute(issuer)
	if err != nil {
		return nil, err
	}
	origin, err := Origin(issuer)
	if err != nil {
		return nil, err
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	inserted := origin + "/.well-known/" + suffix + path
	appended := origin + path + "/.well-known/" + suffix
	if inserted == appended {
		return []string{inserted}, nil
	}
	return []string{inserted, appended}, nil
}
