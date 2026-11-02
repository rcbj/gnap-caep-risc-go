// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const pollMethod = "urn:ietf:rfc:8936"

var signatureRetry = regexp.MustCompile(`publishes no|signing key|does not verify`)

// Logger receives receiver progress. A nil logger prints.
type Logger interface {
	Info(string)
	Warn(string)
	Error(string)
}

type printLogger struct{}

func (printLogger) Info(message string)  { fmt.Println(message) }
func (printLogger) Warn(message string)  { fmt.Println(message) }
func (printLogger) Error(message string) { fmt.Println(message) }

// SSFRequest is one transmitter call. Body is set when the call has one.
type SSFRequest struct {
	Method string
	URL    string
	Body   string
}

// SignalEvent is one event from a Security Event Token.
type SignalEvent struct {
	Type     string
	Payload  any
	Subject  map[string]string
	JTI      string
	Sessions []string
	Ended    bool
	IAT      *float64
	Txn      string
}

// ReceiverOpt tunes one poll receiver.
type ReceiverOpt struct {
	TLS             TLSOpt
	Headers         func(SSFRequest) map[string]string
	EventsRequested []string
	EndOn           []string
	Description     string
	PollIntervalMs  int
	MaxEvents       int
	Log             Logger
}

type pollFlight struct {
	done chan struct{}
	more bool
	err  error
}

// SignalsReceiver polls one Shared Signals stream. Stop waits until the poll Start already had in flight has finished.
type SignalsReceiver struct {
	Stream      map[string]any
	transmitter string
	tls         TLSOpt
	headers     func(SSFRequest) map[string]string
	events      []string
	endOn       []string
	description string
	interval    int
	maxEvents   int
	log         Logger
	onEnd       func([]string, *SignalEvent)
	index       *memoryIndex
	config      map[string]any
	keys        []map[string]any
	keysAt      float64
	running     bool
	ack         []string
	errs        map[string]map[string]string
	handlers    map[string][]func(*SignalEvent)
	mu          sync.Mutex
	gate        sync.Mutex
	flight      *pollFlight
	stopCh      chan struct{}
	doneCh      chan struct{}
	stopOnce    sync.Once
}

// NewSignalsReceiver builds a receiver. onEndSessions is required. The transmitter is an http(s) URL.
func NewSignalsReceiver(transmitter string, onEnd func([]string, *SignalEvent), opt ReceiverOpt) (*SignalsReceiver, error) {
	if onEnd == nil {
		return nil, fail("config", "onEndSessions is required")
	}
	if !strings.HasPrefix(transmitter, "https://") && !strings.HasPrefix(transmitter, "http://") {
		return nil, fail("config", "transmitter must be an http(s) URL")
	}
	events := opt.EventsRequested
	if events == nil {
		events = append([]string{}, DefaultEventsRequested...)
	}
	endOn := opt.EndOn
	if endOn == nil {
		endOn = append([]string{}, DefaultEndingEvents...)
	}
	interval := opt.PollIntervalMs
	if interval == 0 {
		interval = 5000
	}
	maxEvents := opt.MaxEvents
	if maxEvents == 0 {
		maxEvents = 50
	}
	logger := opt.Log
	if logger == nil {
		logger = printLogger{}
	}
	return &SignalsReceiver{
		transmitter: strings.TrimRight(transmitter, "/"),
		tls:         opt.TLS,
		headers:     opt.Headers,
		events:      events,
		endOn:       endOn,
		description: opt.Description,
		interval:    interval,
		maxEvents:   maxEvents,
		log:         logger,
		onEnd:       onEnd,
		index:       newMemoryIndex(),
		errs:        map[string]map[string]string{},
		handlers:    map[string][]func(*SignalEvent){},
	}, nil
}

// Track remembers a local session.
func (r *SignalsReceiver) Track(session TrackedSession) {
	r.mu.Lock()
	r.index.add(session)
	r.mu.Unlock()
}

// Untrack forgets a local session.
func (r *SignalsReceiver) Untrack(localID string) {
	r.mu.Lock()
	r.index.remove(localID)
	r.mu.Unlock()
}

// On registers a handler for one event type, or "*" for every event.
func (r *SignalsReceiver) On(eventType string, handler func(*SignalEvent)) *SignalsReceiver {
	r.mu.Lock()
	r.handlers[eventType] = append(r.handlers[eventType], handler)
	r.mu.Unlock()
	return r
}

func (r *SignalsReceiver) call(method, rawURL string, body any) (int, string, error) {
	var text *string
	if body != nil {
		dumped, err := Dump(body)
		if err != nil {
			return 0, "", err
		}
		text = &dumped
	}
	headers := map[string]string{"accept": "application/json"}
	if r.headers != nil {
		req := SSFRequest{Method: method, URL: rawURL}
		if text != nil {
			req.Body = *text
		}
		for name, value := range r.headers(req) {
			headers[strings.ToLower(name)] = value
		}
	}
	if text != nil {
		if _, ok := headers["content-type"]; !ok {
			headers["content-type"] = "application/json"
		}
	}
	answer, err := Send(rawURL, method, headers, text, r.tls, "ssf")
	if err != nil {
		return 0, "", err
	}
	return answer.Status, answer.Body, nil
}

func (r *SignalsReceiver) discover() error {
	urls, err := WellKnown(r.transmitter, "ssf-configuration")
	if err != nil {
		return err
	}
	last := fmtFail("ssf", "no transmitter configuration at %s", strings.Join(urls, " or "))
	for i, one := range urls {
		status, raw, err := r.call("GET", one, nil)
		if err != nil {
			return err
		}
		if status == 404 && i != len(urls)-1 {
			continue
		}
		parsed, jerr := DecodeJSON(raw)
		doc, ok := AsMap(parsed)
		if jerr != nil || status != 200 || !ok || str(doc["configuration_endpoint"]) == "" || str(doc["jwks_uri"]) == "" {
			last = fmtFail("ssf", "%s answered %d without a usable transmitter configuration", one, status)
			continue
		}
		if methods, ok := AsList(doc["delivery_methods_supported"]); ok && len(methods) > 0 {
			found := false
			for _, item := range methods {
				if str(item) == pollMethod {
					found = true
					break
				}
			}
			if !found {
				return fail("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
			}
		}
		r.config = doc
		return nil
	}
	return last
}

func (r *SignalsReceiver) jwks(force bool) ([]map[string]any, error) {
	if !force && len(r.keys) > 0 && float64(time.Now().UnixMilli())-r.keysAt < 3600000 {
		return r.keys, nil
	}
	status, raw, err := r.call("GET", str(r.config["jwks_uri"]), nil)
	if err != nil {
		return nil, err
	}
	parsed, _ := DecodeJSON(raw)
	doc, _ := AsMap(parsed)
	list, ok := AsList(doc["keys"])
	if status != 200 || !ok {
		return nil, fmtFail("ssf", "the transmitter's JWKS answered %d", status)
	}
	keys := make([]map[string]any, 0, len(list))
	for _, item := range list {
		one, ok := AsMap(item)
		if ok {
			keys = append(keys, one)
		}
	}
	r.keys = keys
	r.keysAt = float64(time.Now().UnixMilli())
	return keys, nil
}

func (r *SignalsReceiver) ensureStream() error {
	endpoint := str(r.config["configuration_endpoint"])
	status, raw, err := r.call("GET", endpoint, nil)
	if err != nil {
		return err
	}
	if status == 200 {
		parsed, _ := DecodeJSON(raw)
		var streams []any
		if list, ok := AsList(parsed); ok {
			streams = list
		} else if parsed != nil {
			streams = []any{parsed}
		}
		for _, item := range streams {
			stream, ok := AsMap(item)
			if !ok || str(stream["stream_id"]) == "" {
				continue
			}
			delivery, _ := AsMap(stream["delivery"])
			if str(delivery["method"]) == pollMethod {
				r.Stream = stream
				return nil
			}
		}
	} else if status != 404 {
		return fmtFail("ssf", "listing the streams at %s answered %d: %s", endpoint, status, clip(raw, 300))
	}
	payload := map[string]any{
		"delivery":         map[string]any{"method": pollMethod},
		"events_requested": r.events,
	}
	if r.description != "" {
		payload["description"] = r.description
	}
	status, raw, err = r.call("POST", endpoint, payload)
	if err != nil {
		return err
	}
	parsed, _ := DecodeJSON(raw)
	created, ok := AsMap(parsed)
	if (status != 200 && status != 201) || !ok || str(created["stream_id"]) == "" {
		return fmtFail("ssf", "creating a stream at %s answered %d: %s", endpoint, status, clip(raw, 300))
	}
	r.Stream = created
	return nil
}

// Start discovers the transmitter, opens one poll stream, and polls in the background.
func (r *SignalsReceiver) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if err := r.discover(); err != nil {
		return err
	}
	if _, err := r.jwks(true); err != nil {
		return err
	}
	if err := r.ensureStream(); err != nil {
		return err
	}
	delivery, _ := AsMap(r.Stream["delivery"])
	endpoint := str(delivery["endpoint_url"])
	if endpoint == "" {
		return fail("ssf", "the stream has no poll endpoint_url")
	}
	delivered, _ := AsList(r.Stream["events_delivered"])
	r.log.Info(fmt.Sprintf("ssf: polling stream %s at %s, delivering %d event type(s)", str(r.Stream["stream_id"]), endpoint, len(delivered)))
	entered := make(chan struct{})
	r.mu.Lock()
	r.running = true
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.mu.Unlock()
	go r.loop(entered)
	<-entered
	return nil
}

// Stop waits until the background poll has finished, so the next poll is a new one.
func (r *SignalsReceiver) Stop() {
	r.mu.Lock()
	done := r.doneCh
	if done == nil {
		r.running = false
		r.mu.Unlock()
		return
	}
	r.running = false
	stop := r.stopCh
	r.mu.Unlock()
	r.stopOnce.Do(func() { close(stop) })
	<-done
}

func (r *SignalsReceiver) loop(entered chan struct{}) {
	defer close(r.doneCh)
	first := true
	for {
		r.mu.Lock()
		running := r.running
		r.mu.Unlock()
		if !running {
			if first {
				close(entered)
			}
			return
		}
		if first {
			first = false
			close(entered)
		}
		delay := r.interval
		more, err := r.PollOnce()
		if err != nil {
			r.log.Warn("ssf: poll failed: " + err.Error())
			delay = r.interval * 4
			if delay > 60000 {
				delay = 60000
			}
		} else if more {
			delay = 0
		}
		r.mu.Lock()
		running = r.running
		stop := r.stopCh
		r.mu.Unlock()
		if !running {
			return
		}
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// PollOnce fetches one batch. A caller that arrives while a poll is running waits for that poll.
func (r *SignalsReceiver) PollOnce() (bool, error) {
	r.gate.Lock()
	if r.flight != nil {
		flight := r.flight
		r.gate.Unlock()
		<-flight.done
		return flight.more, flight.err
	}
	flight := &pollFlight{done: make(chan struct{})}
	r.flight = flight
	r.gate.Unlock()
	flight.more, flight.err = r.pollNow()
	r.gate.Lock()
	if r.flight == flight {
		r.flight = nil
	}
	close(flight.done)
	r.gate.Unlock()
	return flight.more, flight.err
}

func (r *SignalsReceiver) pollNow() (bool, error) {
	delivery, _ := AsMap(r.Stream["delivery"])
	rawURL := str(delivery["endpoint_url"])
	r.mu.Lock()
	ack := append([]string{}, r.ack...)
	r.ack = nil
	setErrs := r.errs
	r.errs = map[string]map[string]string{}
	r.mu.Unlock()
	body := map[string]any{"maxEvents": r.maxEvents, "returnImmediately": true}
	if len(ack) > 0 {
		body["ack"] = ack
	}
	if len(setErrs) > 0 {
		body["setErrs"] = setErrs
	}
	status, raw, err := r.call("POST", rawURL, body)
	if err != nil {
		return false, err
	}
	if status != 200 {
		r.mu.Lock()
		r.ack = append(ack, r.ack...)
		for key, value := range setErrs {
			if _, exists := r.errs[key]; !exists {
				r.errs[key] = value
			}
		}
		r.mu.Unlock()
		return false, fmtFail("ssf", "the poll answered %d: %s", status, clip(raw, 300))
	}
	var envelope struct {
		Sets          json.RawMessage `json:"sets"`
		MoreAvailable bool            `json:"moreAvailable"`
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			return false, failCause("ssf", "the poll answered 200 with a body that is not JSON", err)
		}
	}
	keys, sets, err := orderedSets(envelope.Sets)
	if err != nil {
		return false, err
	}
	for _, jti := range keys {
		if err := r.handle(jti, sets[jti]); err != nil {
			description := err.Error()
			r.log.Warn("ssf: SET " + jti + " refused: " + description)
			code := "invalid_request"
			if ge := asError(err); ge != nil && ge.Code == "signature" {
				code = "invalid_key"
			}
			r.mu.Lock()
			r.errs[jti] = map[string]string{"err": code, "description": description}
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.ack = append(r.ack, jti)
		r.mu.Unlock()
	}
	return envelope.MoreAvailable, nil
}

func orderedSets(raw json.RawMessage) ([]string, map[string]string, error) {
	sets := map[string]string{}
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, sets, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil {
		return nil, nil, failCause("ssf", "the poll sets are not a JSON object", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, nil, fail("ssf", "the poll sets are not a JSON object")
	}
	var keys []string
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, nil, failCause("ssf", "the poll sets are not a JSON object", err)
		}
		key, _ := keyToken.(string)
		var value string
		if err := dec.Decode(&value); err != nil {
			return nil, nil, failCause("ssf", "the poll sets are not a JSON object", err)
		}
		keys = append(keys, key)
		sets[key] = value
	}
	return keys, sets, nil
}

func (r *SignalsReceiver) handle(jti, token string) error {
	keys, err := r.jwks(false)
	if err != nil {
		return err
	}
	verified, err := VerifyCompactJWS(token, keys)
	if err != nil && signatureRetry.MatchString(err.Error()) {
		keys, keyErr := r.jwks(true)
		if keyErr != nil {
			return keyErr
		}
		verified, err = VerifyCompactJWS(token, keys)
	}
	if err != nil {
		return err
	}
	header := verified.Header
	payload := verified.Payload
	if header["typ"] != nil && strings.ToLower(str(header["typ"])) != "secevent+jwt" {
		return fmtFail("validation", "the SET's typ is %s", toString(header["typ"]))
	}
	if str(payload["iss"]) != str(r.config["issuer"]) {
		return fmtFail("validation", "the SET was issued by %s, not %s", toString(payload["iss"]), str(r.config["issuer"]))
	}
	want := audienceList(r.Stream["aud"])
	got := audienceList(payload["aud"])
	if len(want) > 0 {
		match := false
		for _, one := range got {
			if containsString(want, one) {
				match = true
				break
			}
		}
		if !match {
			return fail("validation", "the SET is for "+strings.Join(got, ", ")+", not this stream")
		}
	}
	if payload["jti"] != nil && str(payload["jti"]) != jti {
		return fail("validation", "the SET's jti is not the one it was delivered under")
	}
	events, ok := AsMap(payload["events"])
	if !ok || len(events) == 0 {
		return fail("validation", "the SET carries no events")
	}
	for eventType, eventBody := range events {
		subjectSource := payload["sub_id"]
		if subjectSource == nil {
			if body, ok := AsMap(eventBody); ok {
				subjectSource = body["subject"]
			}
		}
		subject := SubjectOf(subjectSource, str(r.config["issuer"]))
		sessions := r.sessionsFor(eventType, subject)
		ends := containsString(r.endOn, eventType) && len(sessions) > 0
		event := &SignalEvent{
			Type:     eventType,
			Payload:  eventBody,
			Subject:  subject,
			JTI:      jti,
			Sessions: sessions,
			Ended:    ends,
			Txn:      str(payload["txn"]),
		}
		if n, ok := AsFloat(payload["iat"]); ok {
			event.IAT = &n
		}
		if payload["txn"] == nil {
			event.Txn = ""
		}
		if ends {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						r.log.Error(fmt.Sprintf("ssf: onEndSessions threw for %s (SET %s is still acknowledged): %v", eventType, jti, recovered))
						event.Ended = false
					}
				}()
				r.onEnd(sessions, event)
			}()
			if event.Ended {
				r.mu.Lock()
				for _, localID := range sessions {
					r.index.remove(localID)
				}
				r.mu.Unlock()
			}
		}
		r.mu.Lock()
		handlers := append([]func(*SignalEvent){}, r.handlers[eventType]...)
		handlers = append(handlers, r.handlers["*"]...)
		r.mu.Unlock()
		for _, handler := range handlers {
			func(handler func(*SignalEvent)) {
				defer func() {
					if recovered := recover(); recovered != nil {
						r.log.Error(fmt.Sprintf("ssf: a handler for %s threw (SET %s is still acknowledged): %v", eventType, jti, recovered))
					}
				}()
				handler(event)
			}(handler)
		}
	}
	return nil
}

func audienceList(value any) []string {
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

func (r *SignalsReceiver) sessionsFor(eventType string, subject map[string]string) []string {
	if eventType == EventVerification || eventType == EventStreamUpdated {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if subject["idp_session"] != "" {
		found := r.index.byIDP(subject["idp_session"])
		if len(found) > 0 || eventType == EventSessionRevoked {
			return found
		}
	}
	if subject["person"] != "" {
		return r.index.byPerson(subject["person"])
	}
	if subject["email"] != "" {
		return r.index.byEmail(subject["email"])
	}
	return nil
}

// Verify asks the transmitter to send a verification event.
func (r *SignalsReceiver) Verify(state string) error {
	endpoint := str(r.config["verification_endpoint"])
	if endpoint == "" {
		return fail("ssf", "the transmitter publishes no verification_endpoint")
	}
	body := map[string]any{"stream_id": str(r.Stream["stream_id"])}
	if state != "" {
		body["state"] = state
	}
	status, _, err := r.call("POST", endpoint, body)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return fmtFail("ssf", "verification answered %d", status)
	}
	return nil
}

func clip(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
