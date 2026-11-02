// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

// tlsCa holds iya-sts's whole listener CA trust chain (leaf, TLS Issuing CA,
// Intermediate, Root). These tests serve HTTPS from such a chain and check that
// scripts/trust_chain.py (what scripts/configure_iya_sts.py calls) writes all
// of it to the file tlsCa names, from GET /tls/server-certificate and from the
// handshake when that is missing; that the library takes that file as its
// trust store, reading every certificate in it; and that trusting it is not
// trusting anything that names it: a leaf another CA signed is refused even
// when the real CA certificates follow it, and the host name must match the
// leaf's subjectAltName on both of verifyPinned's paths (the pinned leaf and
// the chain to an anchor). The test image carries python3 and openssl.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

type testChain struct {
	// pem is leaf first, Root last: what iya-sts publishes and presents.
	pem  string
	leaf issued
	// cas is the three CA certificates, Issuing CA first.
	cas string
}

var serial int64 = 100

func issue(t *testing.T, cn string, parent *issued, ca bool, dns []string, ips []string) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		DNSNames:              dns,
	}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return issued{cert: cert, key: key, pem: text}
}

func makeChain(t *testing.T, dns []string, ips []string) testChain {
	t.Helper()
	root := issue(t, "test Root CA", nil, true, nil, nil)
	intermediate := issue(t, "test Intermediate CA", &root, true, nil, nil)
	issuing := issue(t, "test TLS Issuing CA", &intermediate, true, nil, nil)
	leaf := issue(t, "127.0.0.1", &issuing, false, dns, ips)
	cas := issuing.pem + intermediate.pem + root.pem
	return testChain{pem: leaf.pem + cas, leaf: leaf, cas: cas}
}

// serveChain answers HTTPS on 127.0.0.1, presenting presented (leaf first) with
// key. published decides whether GET /tls/server-certificate answers presented
// or 404. Every other path answers a small JSON document.
func serveChain(t *testing.T, presented string, key *ecdsa.PrivateKey, published bool) string {
	t.Helper()
	var pair tls.Certificate
	rest := []byte(presented)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pair.Certificate = append(pair.Certificate, block.Bytes)
	}
	pair.PrivateKey = key
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tls/server-certificate" {
			if !published {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("content-type", "text/plain")
			_, _ = io.WriteString(w, presented)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"test"}`)
	})}
	go server.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}))
	t.Cleanup(func() { server.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func blockCount(text string) int {
	return strings.Count(text, "-----BEGIN CERTIFICATE-----")
}

func derOf(t *testing.T, text string) []string {
	t.Helper()
	var out []string
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, string(block.Bytes))
	}
}

// saveWithRegistrar runs the registrar's save step the way the install script
// runs it: the file tlsCa names in a gnap.json, relative to that file's
// directory.
func saveWithRegistrar(t *testing.T, dir, port string) string {
	t.Helper()
	doc, _ := json.Marshal(map[string]any{
		"grantEndpoint": "https://127.0.0.1:" + port + "/gnap",
		"application":   "gnap-caep-risc-demo",
		"tlsCa":         "generated/idp-ca.pem",
	})
	config := filepath.Join(dir, "gnap.json")
	if err := os.WriteFile(config, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "scripts/trust_chain.py", "--config", config)
	cmd.Env = append(os.Environ(), "GNAP_CONFIG=")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil || !strings.Contains(text, "4 certificate(s)") {
		t.Fatalf("trust_chain.py: %v\n%s", err, text)
	}
	if !strings.Contains(text, "trust anchor CN") || !strings.Contains(text, "test Root CA") || !strings.Contains(text, "sha256 ") {
		t.Fatalf("trust_chain.py did not name the anchor:\n%s", text)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "generated", "idp-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return string(saved)
}

// tlsCaOf is tlsCa as the demo's configuration names it, read by the library.
func tlsCaOf(t *testing.T, dir, port string) string {
	t.Helper()
	key, err := CreateSelfSignedKeyPair("gnap-client", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve(map[string]any{
		"grantEndpoint": "https://127.0.0.1:" + port + "/gnap",
		"application":   "gnap-caep-risc-demo",
		"access":        []any{"demo.read"},
		"signals":       false,
		"keyProof":      "mtls",
		"privateKey":    key.PrivateKeyPEM,
		"certificate":   key.CertificatePEM,
		"finishUri":     "http://127.0.0.1:3000/callback",
		"tlsCa":         "file:generated/idp-ca.pem",
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.TLSCA
}

func getWith(rawURL, ca string) (int, error) {
	answer, err := Send(rawURL, "GET", nil, nil, TLSOpt{CA: ca}, "test")
	if err != nil {
		return 0, err
	}
	return answer.Status, nil
}

func mustAccept(t *testing.T, rawURL, ca string) {
	t.Helper()
	status, err := getWith(rawURL, ca)
	if err != nil || status != 200 {
		t.Fatalf("%s: %d %v", rawURL, status, err)
	}
}

func mustRefuse(t *testing.T, rawURL, ca string) {
	t.Helper()
	status, err := getWith(rawURL, ca)
	if err == nil {
		t.Fatalf("%s answered %d; the connection should have been refused", rawURL, status)
	}
	text := strings.ToLower(err.Error())
	if !strings.Contains(text, "certificate") && !strings.Contains(text, "x509") {
		t.Fatalf("%s: refused for another reason: %v", rawURL, err)
	}
}

func writeTrust(t *testing.T, dir, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "generated", "idp-ca.pem"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheRegistrarWritesThePublishedChainToTLSCa(t *testing.T) {
	dir := t.TempDir()
	chain := makeChain(t, []string{"localhost"}, []string{"127.0.0.1"})
	port := serveChain(t, chain.pem, chain.leaf.key, true)
	saved := saveWithRegistrar(t, dir, port)
	if blockCount(saved) != 4 || saved != chain.pem {
		t.Fatalf("saved %d certificate(s), not the published chain:\n%s", blockCount(saved), saved)
	}
}

func TestTheRegistrarFallsBackToTheHandshakeChain(t *testing.T) {
	dir := t.TempDir()
	chain := makeChain(t, []string{"localhost"}, []string{"127.0.0.1"})
	port := serveChain(t, chain.pem, chain.leaf.key, false)
	saved := saveWithRegistrar(t, dir, port)
	if blockCount(saved) != 4 || strings.Join(derOf(t, saved), "|") != strings.Join(derOf(t, chain.pem), "|") {
		t.Fatalf("saved %d certificate(s), not the handshake chain:\n%s", blockCount(saved), saved)
	}
}

func TestTheLibraryTrustsTheWholeChainInTLSCa(t *testing.T) {
	dir := t.TempDir()
	chain := makeChain(t, []string{"localhost"}, []string{"127.0.0.1"})
	port := serveChain(t, chain.pem, chain.leaf.key, true)
	writeTrust(t, dir, chain.pem)
	ca := tlsCaOf(t, dir, port)
	if blockCount(ca) != 4 {
		t.Fatalf("tlsCa resolved to %d certificate(s)", blockCount(ca))
	}
	// The IP literal against the IP SAN, and a DNS name against the DNS SAN.
	mustAccept(t, "https://127.0.0.1:"+port+"/metadata", ca)
	mustAccept(t, "https://localhost:"+port+"/metadata", ca)
}

func TestEveryCertificateInTLSCaIsAnAnchor(t *testing.T) {
	dir := t.TempDir()
	chain := makeChain(t, []string{"localhost"}, []string{"127.0.0.1"})
	port := serveChain(t, chain.pem, chain.leaf.key, true)
	// No leaf to pin, and a first block that anchors nothing here: the Root
	// further down the file is what the presented chain verifies to.
	unrelated := issue(t, "unrelated Root CA", nil, true, nil, nil)
	writeTrust(t, dir, unrelated.pem+chain.cas)
	ca := tlsCaOf(t, dir, port)
	mustAccept(t, "https://127.0.0.1:"+port+"/metadata", ca)
	mustAccept(t, "https://localhost:"+port+"/metadata", ca)
}

func TestTheLibraryChecksTheHostNameAgainstTheLeaf(t *testing.T) {
	// The right chain for a different name: the leaf names only sts.example.com.
	chain := makeChain(t, []string{"sts.example.com"}, nil)
	port := serveChain(t, chain.pem, chain.leaf.key, true)
	// With the leaf in the file (the pinned path) and without it (the chain to
	// an anchor), neither name in the URL is the leaf's.
	for _, ca := range []string{chain.pem, chain.cas} {
		mustRefuse(t, "https://127.0.0.1:"+port+"/metadata", ca)
		mustRefuse(t, "https://localhost:"+port+"/metadata", ca)
	}
}

func TestAForeignLeafFollowedByTheRealCACertificatesIsRefused(t *testing.T) {
	chain := makeChain(t, []string{"localhost"}, []string{"127.0.0.1"})
	// Another CA signs a leaf for the same names; the server sends it followed
	// by the real (public) CA certificates the file trusts.
	other := issue(t, "other Root CA", nil, true, nil, nil)
	forged := issue(t, "127.0.0.1", &other, false, []string{"localhost"}, []string{"127.0.0.1"})
	port := serveChain(t, forged.pem+chain.cas, forged.key, true)
	mustRefuse(t, "https://127.0.0.1:"+port+"/metadata", chain.pem)
	mustRefuse(t, "https://localhost:"+port+"/metadata", chain.pem)
}
