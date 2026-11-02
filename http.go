// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxBytes = 2 * 1024 * 1024

// TLSOpt is the back-channel trust material. CA pins the authorization server. Cert and Key are the mutual TLS client.
type TLSOpt struct {
	CA       string
	Cert     string
	Key      string
	Insecure bool
}

// Answer is one HTTP response. Body is capped at 2 MiB.
type Answer struct {
	Status      int
	ContentType string
	Body        string
}

func verifyPinned(rawCerts [][]byte, caPEM, host string) error {
	if len(rawCerts) == 0 {
		return errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	inter := x509.NewCertPool()
	var pinned []*x509.Certificate
	rest := []byte(caPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		pinned = append(pinned, cert)
		roots.AddCert(cert)
	}
	for _, der := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		inter.AddCert(cert)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: host}
	if _, err := leaf.Verify(opts); err == nil {
		return nil
	}
	for _, cert := range pinned {
		if hmacEqual(cert.Raw, leaf.Raw) {
			return leaf.VerifyHostname(host)
		}
	}
	opts.DNSName = ""
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	return leaf.VerifyHostname(host)
}

// presentClientCertificate always answers a CertificateRequest with the configured pair. GNAP's mtls
// proof registers that certificate by value, and it is usually self-signed, while an authorization
// server such as iya-sts names only its own CA in certificate_authorities. tls.Config.Certificates
// would then match nothing and send no certificate at all, so the proof would fail.
func presentClientCertificate(pair tls.Certificate) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &pair, nil
	}
}

func Send(rawURL, method string, headers map[string]string, body *string, tlsOpt TLSOpt, code string) (*Answer, error) {
	if _, err := parseAbsolute(rawURL); err != nil {
		return nil, fail(code, rawURL+" is not an http(s) URL")
	}
	var payload []byte
	if body != nil {
		payload = []byte(*body)
	}
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, failCause(code, rawURL+": "+err.Error(), err)
	}
	if body != nil {
		req.Body = io.NopCloser(strings.NewReader(*body))
		req.ContentLength = int64(len(payload))
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	host := req.URL.Hostname()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	transport := base.Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if tlsOpt.Insecure {
		cfg.InsecureSkipVerify = true
	} else if tlsOpt.CA != "" {
		cfg.InsecureSkipVerify = true
		ca := tlsOpt.CA
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(rawCerts, ca, host)
		}
	}
	if tlsOpt.Cert != "" && tlsOpt.Key != "" {
		pair, err := tls.X509KeyPair([]byte(tlsOpt.Cert), []byte(tlsOpt.Key))
		if err != nil {
			return nil, failCause(code, rawURL+": "+err.Error(), err)
		}
		cfg.GetClientCertificate = presentClientCertificate(pair)
	}
	transport.TLSClientConfig = cfg
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, failCause(code, rawURL+" did not answer within 15 s", err)
		}
		return nil, failCause(code, rawURL+": "+err.Error(), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, failCause(code, rawURL+": "+err.Error(), err)
	}
	if len(raw) > maxBytes {
		return nil, fmtFail(code, "%s answered more than %d bytes", rawURL, maxBytes)
	}
	return &Answer{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(raw)}, nil
}
