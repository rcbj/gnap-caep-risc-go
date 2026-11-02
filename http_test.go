// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
)

// iya-sts names only its own CA in the CertificateRequest. The client's GNAP certificate is self-signed
// and registered by value, so it must still be sent. tls.Config.Certificates would send none.
func TestPresentsTheSelfSignedClientCertificateWhenTheServerNamesAnotherCA(t *testing.T) {
	serverKey, err := CreateSelfSignedKeyPair("localhost", []string{"localhost"}, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	otherCA, err := CreateSelfSignedKeyPair("some other CA", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := CreateSelfSignedKeyPair("gnap-client", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair([]byte(serverKey.CertificatePEM), []byte(serverKey.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	named := x509.NewCertPool()
	named.AddCert(otherCA.Certificate)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			_, _ = io.WriteString(w, "none")
			return
		}
		_, _ = io.WriteString(w, Fingerprint256(r.TLS.PeerCertificates[0]))
	})}
	go server.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    named,
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}))
	defer server.Close()
	answer, err := Send("https://"+ln.Addr().String()+"/", "GET", nil, nil, TLSOpt{
		CA:   serverKey.CertificatePEM,
		Cert: clientKey.CertificatePEM,
		Key:  clientKey.PrivateKeyPEM,
	}, "protocol")
	if err != nil {
		t.Fatal(err)
	}
	if answer.Body != clientKey.Fingerprint {
		t.Fatalf("the server saw %q, not the client certificate %q", answer.Body, clientKey.Fingerprint)
	}
}
