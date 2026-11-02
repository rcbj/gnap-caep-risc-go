// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	idKey *rsa.PrivateKey
	idJWK map[string]any
	as    *authStub
)

func TestMain(m *testing.M) {
	var err error
	idKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	idJWK = rsaJWK(idKey, "id1")
	as, err = startAuth()
	if err != nil {
		panic(err)
	}
	code := m.Run()
	as.close()
	os.Exit(code)
}

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   B64URL(key.N.Bytes()),
		"e":   B64URL(big.NewInt(int64(key.E)).Bytes()),
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
	}
}

func signJWS(header map[string]any, payload map[string]any, key *rsa.PrivateKey) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := B64URL(hb)
	p := B64URL(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return h + "." + p + "." + B64URL(sig)
}

func idToken(issuer, aud, sub string) string {
	now := time.Now().Unix()
	return signJWS(map[string]any{"alg": "RS256", "kid": "id1", "typ": "JWT"}, map[string]any{
		"iss": issuer, "aud": aud, "sub": sub, "exp": now + 600, "iat": now,
		"email": sub + "@example.com", "sid": "sess-1", "name": "Ada",
	}, idKey)
}

type behavior struct {
	foreign     bool
	bearer      bool
	tooFast     bool
	aud         string
	sub         string
	issSub      string
	omitToken   bool
	tooFastSent bool
}

type seenCall struct {
	Method        string
	URL           string
	Body          string
	Authorization string
	Signature     string
	Detached      string
	Cert          string
}

type authStub struct {
	base        string
	serverCert  string
	clientKey   *KeyPair
	fingerprint string
	server      *http.Server
	mu          sync.Mutex
	seen        []seenCall
	public      *ecdsa.PublicKey
	kid         string
	behavior    behavior
}

func (s *authStub) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = nil
	s.behavior = behavior{aud: "instance-1", sub: "user-1"}
}

func (s *authStub) close() {
	_ = s.server.Close()
}

func startAuth() (*authStub, error) {
	serverKey, err := CreateSelfSignedKeyPair("localhost", []string{"localhost"}, []string{"127.0.0.1"})
	if err != nil {
		return nil, err
	}
	clientKey, err := CreateSelfSignedKeyPair("gnap-client", nil, nil)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(serverKey.CertificatePEM), []byte(serverKey.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	stub := &authStub{serverCert: serverKey.CertificatePEM, clientKey: clientKey, fingerprint: clientKey.Fingerprint, behavior: behavior{aud: "instance-1", sub: "user-1"}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	stub.base = "https://" + ln.Addr().String()
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	stub.server = &http.Server{Handler: http.HandlerFunc(stub.serve)}
	go stub.server.Serve(tlsLn)
	return stub, nil
}

func (s *authStub) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	target := s.base + path
	certFP := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		certFP = Fingerprint256(r.TLS.PeerCertificates[0])
	}
	call := seenCall{
		Method: r.Method, URL: path, Body: string(raw),
		Authorization: r.Header.Get("authorization"), Signature: r.Header.Get("signature"),
		Detached: r.Header.Get("detached-jws"), Cert: certFP,
	}
	s.mu.Lock()
	s.seen = append(s.seen, call)
	s.mu.Unlock()
	if err := s.verify(r, string(raw), target); err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": err.Error()})
		return
	}
	s.mu.Lock()
	b := s.behavior
	if path == "/continue" && r.Method == "POST" && b.tooFast && !b.tooFastSent {
		s.behavior.tooFastSent = true
		b.tooFastSent = false
		s.mu.Unlock()
		writeJSON(w, 400, map[string]any{"error": "too_fast", "continue": map[string]any{"uri": s.base + "/continue", "wait": 0, "access_token": map[string]any{"value": "cont-token"}}})
		return
	}
	s.mu.Unlock()
	switch {
	case r.Method == "OPTIONS" && path == "/gnap":
		writeJSON(w, 200, map[string]any{
			"grant_request_endpoint":               s.base + "/gnap",
			"key_proofs_supported":                 []string{"httpsig", "jwsd", "mtls"},
			"interaction_start_modes_supported":    []string{"redirect"},
			"interaction_finish_methods_supported": []string{"redirect", "push"},
			"sub_id_formats_supported":             []string{"iss_sub", "opaque"},
			"assertion_formats_supported":          []string{"id_token"},
		})
	case path == "/.well-known/openid-configuration":
		writeJSON(w, 200, map[string]any{"issuer": s.base, "jwks_uri": s.base + "/jwks"})
	case path == "/jwks":
		writeJSON(w, 200, map[string]any{"keys": []any{idJWK}})
	case path == "/gnap" && r.Method == "POST":
		cont := s.base + "/continue"
		if b.foreign {
			cont = "https://evil.example/continue"
		}
		writeJSON(w, 200, map[string]any{
			"instance_id": "instance-1",
			"interact":    map[string]any{"redirect": s.base + "/interact/1", "finish": "server-nonce"},
			"continue":    map[string]any{"uri": cont, "wait": 0, "access_token": map[string]any{"value": "cont-token"}},
		})
	case path == "/continue" && r.Method == "POST":
		if r.Header.Get("authorization") != "GNAP cont-token" {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		if b.omitToken {
			writeJSON(w, 200, map[string]any{"instance_id": "instance-1"})
			return
		}
		subjectSub := b.sub
		if b.issSub != "" {
			subjectSub = b.issSub
		}
		token := map[string]any{
			"value": "access-1", "access": []string{"ssf.read", "ssf.manage"}, "expires_in": 3600,
			"manage": map[string]any{"uri": s.base + "/token/grant-9", "access_token": map[string]any{"value": "manage-1"}},
		}
		if b.bearer {
			token["flags"] = []string{"bearer"}
		}
		writeJSON(w, 200, map[string]any{
			"instance_id":  "instance-1",
			"access_token": token,
			"continue":     map[string]any{"uri": s.base + "/continue/grant-9", "access_token": map[string]any{"value": "cont-next"}},
			"subject": map[string]any{
				"sub_ids":    []any{map[string]any{"format": "iss_sub", "iss": s.base, "sub": subjectSub}},
				"assertions": []any{map[string]any{"format": "id_token", "value": idToken(s.base, b.aud, b.sub)}},
			},
		})
	case path == "/token/grant-9" && r.Method == "POST":
		if r.Header.Get("authorization") != "GNAP manage-1" {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": map[string]any{
			"value": "access-2", "expires_in": 3600,
			"manage": map[string]any{"uri": s.base + "/token/grant-9", "access_token": map[string]any{"value": "manage-2"}},
		}})
	case r.Method == "DELETE":
		w.WriteHeader(204)
	default:
		writeJSON(w, 404, map[string]any{"error": "not_found"})
	}
}

func (s *authStub) verify(r *http.Request, raw, target string) error {
	if raw != "" && r.URL.Path == "/gnap" {
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err == nil {
			client, _ := doc["client"].(map[string]any)
			key, _ := client["key"].(map[string]any)
			jwk, _ := key["jwk"].(map[string]any)
			if jwk != nil {
				public, err := PublicKeyFromJWK(jwk)
				if err != nil {
					return err
				}
				if ec, ok := public.(*ecdsa.PublicKey); ok {
					s.mu.Lock()
					s.public = ec
					s.kid = str(jwk["kid"])
					s.mu.Unlock()
				}
			}
		}
	}
	if r.Header.Get("signature") != "" {
		if err := s.verifyHTTPSig(r, raw, target); err != nil {
			return err
		}
	}
	if r.Header.Get("detached-jws") != "" {
		if err := s.verifyJWSD(r, raw, target); err != nil {
			return err
		}
	}
	return nil
}

var sigInputRE = regexp.MustCompile(`^sig1=\(([^)]*)\)(.*)$`)
var sigRE = regexp.MustCompile(`^sig1=:([A-Za-z0-9+/=]*):$`)
var componentRE = regexp.MustCompile(`"([^"]+)"`)

func (s *authStub) verifyHTTPSig(r *http.Request, raw, target string) error {
	input := r.Header.Get("signature-input")
	if strings.Contains(input, ";alg=") {
		return errString("alg parameter")
	}
	match := sigInputRE.FindStringSubmatch(input)
	if match == nil {
		return errString(input)
	}
	components := componentRE.FindAllStringSubmatch(match[1], -1)
	names := make([]string, len(components))
	quoted := make([]string, len(components))
	for i, item := range components {
		names[i] = item[1]
		quoted[i] = `"` + item[1] + `"`
	}
	serialised := "(" + strings.Join(quoted, " ") + ")" + match[2]
	if !strings.Contains(match[2], `tag="gnap"`) {
		return errString("tag")
	}
	s.mu.Lock()
	kid := s.kid
	public := s.public
	s.mu.Unlock()
	if !strings.Contains(match[2], `keyid="`+kid+`"`) {
		return errString("keyid")
	}
	var lines []string
	for _, component := range names {
		value := ""
		switch component {
		case "@method":
			value = strings.ToUpper(r.Method)
		case "@target-uri":
			value = target
		default:
			value = strings.TrimSpace(r.Header.Get(component))
		}
		lines = append(lines, `"`+component+`": `+value)
	}
	lines = append(lines, `"@signature-params": `+serialised)
	sigMatch := sigRE.FindStringSubmatch(r.Header.Get("signature"))
	if sigMatch == nil {
		return errString("signature")
	}
	signature, err := base64.StdEncoding.DecodeString(sigMatch[1])
	if err != nil || len(signature) == 0 || len(signature)%2 != 0 || public == nil {
		return errString("signature bytes")
	}
	size := len(signature) / 2
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	if !ecdsa.Verify(public, sum[:], new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])) {
		return errString("httpsig verify")
	}
	if raw != "" {
		digest := "sha-256=:" + base64.StdEncoding.EncodeToString(SHA256([]byte(raw))) + ":"
		if r.Header.Get("content-digest") != digest {
			return errString("content-digest")
		}
	}
	return nil
}

func (s *authStub) verifyJWSD(r *http.Request, raw, target string) error {
	parts := strings.Split(r.Header.Get("detached-jws"), ".")
	if len(parts) != 3 {
		return errString("detached")
	}
	headerRaw, err := B64URLDecode(parts[0])
	if err != nil {
		return err
	}
	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return err
	}
	if str(header["typ"]) != "gnap-binding-jwsd" || str(header["alg"]) != "ES256" {
		return errString("jws header")
	}
	s.mu.Lock()
	kid := s.kid
	public := s.public
	s.mu.Unlock()
	if str(header["kid"]) != kid || str(header["htm"]) != strings.ToUpper(r.Method) || str(header["uri"]) != target {
		return errString("jws claim")
	}
	token := strings.TrimPrefix(r.Header.Get("authorization"), "GNAP ")
	if r.Header.Get("authorization") != "" {
		if str(header["ath"]) != B64URL(SHA256([]byte(token))) {
			return errString("ath")
		}
	} else if _, ok := header["ath"]; ok {
		return errString("ath present")
	}
	payload := ""
	if raw != "" {
		payload = B64URL(SHA256([]byte(raw)))
	}
	if parts[1] != payload {
		return errString("payload")
	}
	signature, err := B64URLDecode(parts[2])
	if err != nil || public == nil || len(signature)%2 != 0 {
		return errString("jws signature")
	}
	size := len(signature) / 2
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(public, sum[:], new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])) {
		return errString("jwsd verify")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	raw, _ := json.Marshal(body)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

type errString string

func (e errString) Error() string { return string(e) }

func clientFor(t *testing.T, proof string, extra map[string]any) *Client {
	t.Helper()
	body := map[string]any{
		"grantEndpoint":    as.base + "/gnap",
		"idTokenIssuer":    as.base,
		"application":      "gnap-caep-risc-demo",
		"display":          map[string]any{"name": "GNAP CAEP RISC demo", "uri": "http://127.0.0.1:3000/"},
		"access":           []any{"ssf.read", "ssf.manage"},
		"subIdFormats":     []any{"iss_sub", "account", "opaque"},
		"assertionFormats": []any{"id_token"},
		"keyProof":         proof,
		"privateKey":       as.clientKey.PrivateKeyPEM,
		"certificate":      as.clientKey.CertificatePEM,
		"finishUri":        "http://127.0.0.1:3000/callback",
		"finishMethod":     "redirect",
		"tlsCa":            as.serverCert,
	}
	for key, value := range extra {
		body[key] = value
	}
	cfg, err := Resolve(body, ".")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

func started(t *testing.T, gnap *Client) (*GrantResult, map[string]any) {
	t.Helper()
	result, err := gnap.RequestGrant()
	if err != nil {
		t.Fatal(err)
	}
	if result.Pending == nil {
		t.Fatal("missing pending")
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	var body string
	for _, call := range as.seen {
		if call.Method == "POST" && call.URL == "/gnap" {
			body = call.Body
		}
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return result, doc
}

func finishHash(clientNonce, interactRef string) string {
	return B64URL(SHA256([]byte(clientNonce + "\nserver-nonce\n" + interactRef + "\n" + as.base + "/gnap")))
}

func nonceOf(request map[string]any) string {
	interact, _ := request["interact"].(map[string]any)
	finish, _ := interact["finish"].(map[string]any)
	return str(finish["nonce"])
}

func TestInteractionHashVector(t *testing.T) {
	if InteractionHash("abc", "def", "xyz", "https://as.example/gnap") != "2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0" {
		t.Fatal(InteractionHash("abc", "def", "xyz", "https://as.example/gnap"))
	}
}

func TestRefusesFrontChannelForeignAndAHashThatIsNotOurs(t *testing.T) {
	as.reset()
	gnap := clientFor(t, "httpsig", nil)
	as.mu.Lock()
	as.behavior.foreign = true
	as.mu.Unlock()
	_, err := gnap.RequestGrant()
	if err == nil || !strings.Contains(err.Error(), "not on the grant endpoint") {
		t.Fatal(err)
	}
	as.mu.Lock()
	for _, call := range as.seen {
		if call.URL == "/continue" {
			t.Fatal("continue was called")
		}
	}
	as.behavior.foreign = false
	as.seen = nil
	as.mu.Unlock()
	presenting := clientFor(t, "httpsig", nil)
	result, request := started(t, presenting)
	client, _ := request["client"].(map[string]any)
	key, _ := client["key"].(map[string]any)
	if str(key["proof"]) != "httpsig" {
		t.Fatal(key)
	}
	if _, ok := client["class_id"]; ok {
		t.Fatal("class_id")
	}
	subject, _ := request["subject"].(map[string]any)
	if !reflectStrings(subject["sub_id_formats"], []string{"iss_sub", "opaque"}) {
		t.Fatal(subject)
	}
	as.mu.Lock()
	if len(as.seen) == 0 || as.seen[len(as.seen)-1].Signature == "" {
		t.Fatal("missing signature")
	}
	as.mu.Unlock()
	digest := finishHash(nonceOf(request), "ref-1")
	_, err = presenting.FinishRedirect("hash="+digest+"&interact_ref=ref-1&access_token=no", []string{result.Pending.ID})
	if err == nil || !strings.Contains(err.Error(), "tokens through the browser") || strings.Contains(err.Error(), "front") {
		t.Fatal(err)
	}
	_, err = presenting.FinishRedirect("hash="+digest+"&interact_ref=ref-1", []string{"somebody-else"})
	if err == nil || !strings.Contains(err.Error(), "this browser") {
		t.Fatal(err)
	}
	as.mu.Lock()
	for _, call := range as.seen {
		if call.URL == "/continue" {
			t.Fatal("continue was called")
		}
	}
	as.mu.Unlock()
	_, err = presenting.FinishRedirect("hash=nope&interact_ref=ref-1", []string{result.Pending.ID})
	if err == nil || !strings.Contains(err.Error(), "this browser") {
		t.Fatal(err)
	}
}

func reflectStrings(value any, want []string) bool {
	list, ok := value.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	for i, item := range want {
		if str(list[i]) != item {
			return false
		}
	}
	return true
}

func TestFinishesARedirectChecksTheIDTokenAndRotates(t *testing.T) {
	as.reset()
	as.mu.Lock()
	as.behavior.tooFast = true
	as.mu.Unlock()
	gnap := clientFor(t, "httpsig", nil)
	result, request := started(t, gnap)
	digest := finishHash(nonceOf(request), "ref-1")
	done, err := gnap.FinishRedirect(map[string]string{"hash": digest, "interact_ref": "ref-1"}, []string{result.Pending.ID})
	if err != nil {
		t.Fatal(err)
	}
	if done.Grant.AccessToken != "access-1" || done.Grant.Bearer || done.Grant.Subject == nil || done.Grant.Subject.Sub != "user-1" {
		t.Fatalf("%#v", done.Grant)
	}
	if done.Grant.Subject.Email != "user-1@example.com" || done.Grant.Subject.Sid != "sess-1" || !done.Grant.Subject.AssertionVerified || done.Grant.GrantID != "grant-9" {
		t.Fatalf("%#v", done.Grant.Subject)
	}
	as.mu.Lock()
	if !as.behavior.tooFastSent {
		as.mu.Unlock()
		t.Fatal("too_fast was not sent")
	}
	as.mu.Unlock()
	again, err := gnap.RequestGrant()
	if err != nil || again.Pending == nil {
		t.Fatal(err)
	}
	as.mu.Lock()
	var second string
	for _, call := range as.seen {
		if call.URL == "/gnap" && call.Method == "POST" {
			second = call.Body
		}
	}
	as.mu.Unlock()
	var doc map[string]any
	if err := json.Unmarshal([]byte(second), &doc); err != nil {
		t.Fatal(err)
	}
	if str(doc["client"]) != "instance-1" {
		t.Fatalf("client %#v", doc["client"])
	}
	rotated, err := gnap.Rotate(done.Grant)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessToken != "access-2" || rotated.Subject == nil || rotated.Subject.Sub != "user-1" || rotated.Continuation.URI != done.Grant.Continuation.URI {
		t.Fatalf("%#v", rotated)
	}
	if err := gnap.Revoke(rotated); err != nil {
		t.Fatal(err)
	}
	as.mu.Lock()
	if as.seen[len(as.seen)-1].Method != "DELETE" {
		as.mu.Unlock()
		t.Fatal(as.seen[len(as.seen)-1].Method)
	}
	as.mu.Unlock()
	_, err = gnap.FinishRedirect(map[string]string{"hash": digest, "interact_ref": "ref-1"}, []string{result.Pending.ID})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatal(err)
	}
}

func TestProvesTheKeyWithDetachedJWSAndMutualTLS(t *testing.T) {
	as.reset()
	jwsd := clientFor(t, "jwsd", nil)
	firstResult, first := started(t, jwsd)
	client, _ := first["client"].(map[string]any)
	key, _ := client["key"].(map[string]any)
	if str(key["proof"]) != "jwsd" {
		t.Fatal(key)
	}
	digest := finishHash(nonceOf(first), "ref-j")
	done, err := jwsd.FinishRedirect("?hash="+digest+"&interact_ref=ref-j", []string{firstResult.Pending.ID})
	if err != nil {
		t.Fatal(err)
	}
	if done.Grant.Subject == nil || done.Grant.Subject.Name != "Ada" {
		t.Fatal(done.Grant.Subject)
	}
	as.mu.Lock()
	foundDetached := false
	for _, call := range as.seen {
		if call.URL == "/continue" && strings.Contains(call.Detached, ".") {
			foundDetached = true
		}
	}
	var continueSig string
	for _, call := range as.seen {
		if call.URL == "/continue" {
			continueSig = call.Signature
			break
		}
	}
	as.mu.Unlock()
	if !foundDetached || continueSig != "" {
		t.Fatalf("detached %v sig %q", foundDetached, continueSig)
	}
	as.mu.Lock()
	as.seen = nil
	as.mu.Unlock()
	mtls := clientFor(t, "mtls", nil)
	secondResult, second := started(t, mtls)
	client, _ = second["client"].(map[string]any)
	key, _ = client["key"].(map[string]any)
	if str(key["proof"]) != "mtls" {
		t.Fatal(key)
	}
	as.mu.Lock()
	var gnapCall seenCall
	for _, call := range as.seen {
		if call.URL == "/gnap" {
			gnapCall = call
			break
		}
	}
	as.mu.Unlock()
	if gnapCall.Cert != as.fingerprint || gnapCall.Signature != "" || gnapCall.Detached != "" {
		t.Fatalf("%#v want %s", gnapCall, as.fingerprint)
	}
	digest2 := finishHash(nonceOf(second), "ref-m")
	finished, err := mtls.FinishPush(map[string]any{"hash": digest2, "interact_ref": "ref-m"})
	if err != nil {
		t.Fatal(err)
	}
	if finished.Grant.AccessToken != "access-1" {
		t.Fatal(finished.Grant.AccessToken)
	}
	answer, err := mtls.Call(finished.Grant, as.base+"/jwks", "GET", nil, nil)
	if err != nil || answer.Status != 200 {
		t.Fatal(err, answer)
	}
	as.mu.Lock()
	auth := as.seen[len(as.seen)-1].Authorization
	as.mu.Unlock()
	if auth != "GNAP access-1" || secondResult.Pending.ID == "" {
		t.Fatal(auth)
	}
}

func TestRefusesBearerBadAudienceAndASubjectThatDoesNotMatch(t *testing.T) {
	as.reset()
	as.mu.Lock()
	as.behavior.bearer = true
	as.mu.Unlock()
	gnap := clientFor(t, "httpsig", nil)
	result, request := started(t, gnap)
	digest := finishHash(nonceOf(request), "ref-b")
	_, err := gnap.FinishRedirect(map[string]string{"hash": digest, "interact_ref": "ref-b"}, []string{result.Pending.ID})
	ge, _ := err.(*Error)
	if err == nil || ge == nil || ge.Code != "validation" || !strings.Contains(err.Error(), "bearer") {
		t.Fatal(err)
	}
	as.mu.Lock()
	as.behavior.bearer = false
	as.behavior.aud = "someone-else"
	as.mu.Unlock()
	audience := clientFor(t, "httpsig", nil)
	nextResult, nextRequest := started(t, audience)
	digest2 := finishHash(nonceOf(nextRequest), "ref-a")
	_, err = audience.FinishRedirect(map[string]string{"hash": digest2, "interact_ref": "ref-a"}, []string{nextResult.Pending.ID})
	if err == nil || !strings.Contains(err.Error(), "id_token is for") {
		t.Fatal(err)
	}
	as.mu.Lock()
	as.behavior.aud = "gnap-caep-risc-demo"
	as.behavior.issSub = "other-user"
	as.behavior.sub = "user-1"
	as.mu.Unlock()
	thirdResult, third := started(t, gnap)
	digest3 := finishHash(nonceOf(third), "ref-s")
	_, err = gnap.FinishRedirect(map[string]string{"hash": digest3, "interact_ref": "ref-s"}, []string{thirdResult.Pending.ID})
	if err == nil || !strings.Contains(err.Error(), "somebody other") {
		t.Fatal(err)
	}
}

func TestAcceptsTheApplicationIdentifierAsTheIDTokenAudience(t *testing.T) {
	as.reset()
	as.mu.Lock()
	as.behavior.aud = "gnap-caep-risc-demo"
	as.behavior.sub = "user-2"
	as.mu.Unlock()
	gnap := clientFor(t, "httpsig", nil)
	result, request := started(t, gnap)
	digest := finishHash(nonceOf(request), "ref-app")
	done, err := gnap.FinishRedirect(map[string]string{"hash": digest, "interact_ref": "ref-app"}, []string{result.Pending.ID})
	if err != nil {
		t.Fatal(err)
	}
	if done.Grant.Subject == nil || done.Grant.Subject.Sub != "user-2" {
		t.Fatal(done.Grant.Subject)
	}
	soon := float64(time.Now().UnixMilli() + 10000)
	done.Grant.ExpiresAt = &soon
	fresh, err := gnap.EnsureFresh(done.Grant)
	if err != nil || fresh.AccessToken != "access-2" {
		t.Fatal(err, fresh)
	}
	later := float64(time.Now().UnixMilli() + 3600000)
	fresh.ExpiresAt = &later
	held, err := gnap.EnsureFresh(fresh)
	if err != nil || held.AccessToken != "access-2" {
		t.Fatal(err)
	}
}

func TestCertificateChainPutsTheLeafInTheKeyAndTheChainOnTLS(t *testing.T) {
	leaf, err := CreateSelfSignedKeyPair("leaf.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := CreateSelfSignedKeyPair("issuer.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := strings.TrimSpace(leaf.CertificatePEM) + "\n" + strings.TrimSpace(issuer.CertificatePEM) + "\n"
	key, err := LoadClientKey(leaf.PrivateKeyPEM, chain, "mtls")
	if err != nil {
		t.Fatal(err)
	}
	published, err := PublicKeyObject(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(str(published["cert"]), "BEGIN CERTIFICATE") != 1 {
		t.Fatal(published["cert"])
	}
	block, _ := pem.Decode([]byte(str(published["cert"])))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil || Fingerprint256(parsed) != leaf.Fingerprint {
		t.Fatal(err, Fingerprint256(parsed), leaf.Fingerprint)
	}
	cfg, err := Resolve(map[string]any{
		"grantEndpoint": "https://as.example/gnap",
		"application":   "chain-demo",
		"keyProof":      "mtls",
		"privateKey":    leaf.PrivateKeyPEM,
		"certificate":   chain,
		"finishUri":     "http://127.0.0.1:9/callback",
	}, ".")
	if err != nil {
		t.Fatal(err)
	}
	tlsOpt, err := New(cfg).TLS()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tlsOpt.Cert, "BEGIN CERTIFICATE") != 2 {
		t.Fatal(tlsOpt.Cert)
	}
}
