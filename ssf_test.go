// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type quietLog struct{}

func (quietLog) Info(string)  {}
func (quietLog) Warn(string)  {}
func (quietLog) Error(string) {}

func TestVerifiesASETAndRefusesAnotherKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := rsaJWK(private, "k1")
	good := signJWS(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}, map[string]any{"a": 1}, private)
	verified, err := VerifyCompactJWS(good, []map[string]any{jwk})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := AsFloat(verified.Payload["a"]); !ok || got != 1 {
		t.Fatalf("%#v", verified.Payload)
	}
	badKey := signJWS(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}, map[string]any{"a": 1}, other)
	if _, err := VerifyCompactJWS(badKey, []map[string]any{jwk}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatal(err)
	}
	badKid := signJWS(map[string]any{"alg": "RS256", "kid": "nope"}, map[string]any{"a": 1}, private)
	if _, err := VerifyCompactJWS(badKid, []map[string]any{jwk}); err == nil || !strings.Contains(err.Error(), "kid nope") {
		t.Fatal(err)
	}
	none := signJWS(map[string]any{"alg": "none"}, map[string]any{"a": 1}, private)
	if _, err := VerifyCompactJWS(none, []map[string]any{jwk}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatal(err)
	}
}

func TestReadsSubjectForms(t *testing.T) {
	if EventSessionRevoked != "https://schemas.openid.net/secevent/caep/event-type/session-revoked" {
		t.Fatal(EventSessionRevoked)
	}
	if EventCredentialCompromise != "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" {
		t.Fatal(EventCredentialCompromise)
	}
	got := SubjectOf(map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
		"session": map[string]any{"format": "opaque", "id": "S1"},
	}, "https://i")
	want := map[string]string{"person": "urn:uuid:a", "idp_session": "S1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v", got)
	}
	if len(SubjectOf(map[string]any{"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i")) != 0 {
		t.Fatal("issuer mismatch")
	}
	email := SubjectOf(map[string]any{"format": "email", "email": "A@x.com"}, "https://i")
	if !reflect.DeepEqual(email, map[string]string{"email": "A@x.com"}) {
		t.Fatalf("%#v", email)
	}
}

type txState struct {
	mu            sync.Mutex
	queue         []txItem
	acked         []string
	errs          map[string]map[string]string
	streams       int
	authorization string
	base          string
}

type txItem struct {
	jti   string
	token string
}

func (s *txState) deliver(eventType string, subID map[string]any, extra map[string]any, key *rsa.PrivateKey) string {
	jti := randomJTI()
	body := map[string]any{"event_timestamp": 1}
	for k, v := range extra {
		body[k] = v
	}
	if key == nil {
		key = ssfKey
	}
	token := signJWS(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}, map[string]any{
		"iss": s.base, "aud": "my-app", "jti": jti, "iat": 1, "sub_id": subID, "events": map[string]any{eventType: body},
	}, key)
	s.mu.Lock()
	s.queue = append(s.queue, txItem{jti, token})
	s.mu.Unlock()
	return jti
}

var ssfKey *rsa.PrivateKey
var ssfOther *rsa.PrivateKey
var ssfJWK map[string]any

func initSSFKeys(t *testing.T) {
	t.Helper()
	if ssfKey != nil {
		return
	}
	var err error
	ssfKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ssfOther, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ssfJWK = rsaJWK(ssfKey, "k1")
}

func randomJTI() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return B64URL(buf)
}

func startTransmitter(t *testing.T) *txState {
	t.Helper()
	initSSFKeys(t)
	state := &txState{errs: map[string]map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		path := r.URL.Path
		state.mu.Lock()
		state.authorization = r.Header.Get("authorization")
		auth := state.authorization
		state.mu.Unlock()
		if auth != "GNAP app-token" && path != "/.well-known/ssf-configuration" && !strings.HasPrefix(path, "/jwks") {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		switch {
		case path == "/.well-known/ssf-configuration" && r.Method == "GET":
			writeJSON(w, 200, map[string]any{
				"issuer": state.base, "jwks_uri": state.base + "/jwks",
				"configuration_endpoint":     state.base + "/ssf/stream",
				"verification_endpoint":      state.base + "/ssf/verify",
				"delivery_methods_supported": []string{pollMethod},
			})
		case path == "/jwks":
			writeJSON(w, 200, map[string]any{"keys": []any{ssfJWK}})
		case path == "/ssf/stream" && r.Method == "GET":
			writeJSON(w, 200, []any{})
		case path == "/ssf/stream" && r.Method == "POST":
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			state.mu.Lock()
			state.streams++
			id := state.streams
			state.mu.Unlock()
			delivery, _ := body["delivery"].(map[string]any)
			stream := map[string]any{
				"stream_id": "s" + itoa(id), "iss": state.base, "aud": "my-app",
				"delivery":         map[string]any{"method": delivery["method"], "endpoint_url": state.base + "/ssf/poll/s" + itoa(id)},
				"events_requested": body["events_requested"],
				"events_delivered": body["events_requested"],
			}
			writeJSON(w, 201, stream)
		case path == "/ssf/verify":
			w.WriteHeader(204)
		case strings.HasPrefix(path, "/ssf/poll/"):
			var body struct {
				Ack     []string                     `json:"ack"`
				SetErrs map[string]map[string]string `json:"setErrs"`
			}
			_ = json.Unmarshal(raw, &body)
			state.mu.Lock()
			for _, jti := range body.Ack {
				state.acked = append(state.acked, jti)
				state.drop(jti)
			}
			for jti, errDoc := range body.SetErrs {
				state.errs[jti] = errDoc
				state.drop(jti)
			}
			payload := state.setsJSON()
			state.mu.Unlock()
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(payload))
		default:
			writeJSON(w, 404, map[string]any{"error": "not_found"})
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	state.base = "http://" + ln.Addr().String()
	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	t.Cleanup(func() { _ = server.Close() })
	return state
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func (s *txState) drop(jti string) {
	var next []txItem
	for _, item := range s.queue {
		if item.jti != jti {
			next = append(next, item)
		}
	}
	s.queue = next
}

func (s *txState) setsJSON() string {
	var b strings.Builder
	b.WriteString(`{"sets":{`)
	for i, item := range s.queue {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(item.jti)
		val, _ := json.Marshal(item.token)
		b.Write(key)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteString(`},"moreAvailable":false}`)
	return b.String()
}

func TestPollsWithTheGNAPTokenAndAcknowledges(t *testing.T) {
	state := startTransmitter(t)
	var ended [][]string
	var seen []*SignalEvent
	var signed []SSFRequest
	var mu sync.Mutex
	receiver, err := NewSignalsReceiver(state.base, func(ids []string, event *SignalEvent) {
		ended = append(ended, append([]string{}, ids...))
	}, ReceiverOpt{
		Headers: func(request SSFRequest) map[string]string {
			mu.Lock()
			signed = append(signed, request)
			mu.Unlock()
			return map[string]string{"authorization": "GNAP app-token"}
		},
		PollIntervalMs: 60000,
		Log:            quietLog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	receiver.On("*", func(event *SignalEvent) {
		seen = append(seen, event)
	})
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	state.mu.Lock()
	created := state.streams
	auth := state.authorization
	state.mu.Unlock()
	if created != 1 || auth != "GNAP app-token" || str(receiver.Stream["stream_id"]) != "s1" {
		t.Fatalf("created %d auth %s stream %#v", created, auth, receiver.Stream)
	}
	mu.Lock()
	var createBody string
	for _, request := range signed {
		if request.Method == "POST" && strings.HasSuffix(request.URL, "/ssf/stream") {
			createBody = request.Body
		}
	}
	mu.Unlock()
	if !strings.Contains(createBody, `"delivery"`) {
		t.Fatal(createBody)
	}
	receiver.Track(TrackedSession{LocalID: "L-a1", Person: "urn:uuid:alice", Email: "alice@example.com", IDPSession: "IDP-A1"})
	receiver.Track(TrackedSession{LocalID: "L-a2", Person: "urn:uuid:alice", Email: "alice@example.com", IDPSession: "IDP-A2"})
	receiver.Track(TrackedSession{LocalID: "L-b1", Person: "urn:uuid:bob", Email: "bob@example.com", IDPSession: "IDP-B1"})
	revoked := state.deliver(EventSessionRevoked, map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": state.base, "sub": "urn:uuid:alice"},
		"session": map[string]any{"format": "opaque", "id": "IDP-A1"},
	}, nil, ssfKey)
	state.deliver(EventCredentialChange, map[string]any{"format": "iss_sub", "iss": state.base, "sub": "urn:uuid:bob"}, map[string]any{"credential_type": "password"}, ssfKey)
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 1 || len(ended[0]) != 1 || ended[0][0] != "L-a1" || len(seen) != 2 || !seen[0].Ended || seen[1].Type != EventCredentialChange || seen[1].Ended {
		t.Fatalf("ended %#v seen %d", ended, len(seen))
	}
	mu.Lock()
	var poll SSFRequest
	for _, request := range signed {
		if strings.Contains(request.URL, "/ssf/poll/") {
			poll = request
			break
		}
	}
	mu.Unlock()
	if poll.Method != "POST" || !strings.Contains(poll.Body, "maxEvents") {
		t.Fatalf("%#v", poll)
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	acked := append([]string{}, state.acked...)
	state.mu.Unlock()
	if len(acked) == 0 || acked[0] != revoked {
		t.Fatalf("acked %#v revoked %s", acked, revoked)
	}
	rest := []string{revoked}
	for _, item := range acked {
		if item != revoked {
			rest = append(rest, item)
		}
	}
	if !reflect.DeepEqual(acked, rest) {
		t.Fatalf("acked %#v", acked)
	}
	bad := state.deliver(EventAccountDisabled, map[string]any{"format": "email", "email": "alice@example.com"}, nil, ssfOther)
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	errDoc := state.errs[bad]
	state.mu.Unlock()
	if errDoc["err"] != "invalid_key" {
		t.Fatalf("%#v", errDoc)
	}
	if err := receiver.Verify("abc"); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
}

// Keep crypto imported for the RSA signer used by signJWS in this file's tests.
var _ = crypto.SHA256
