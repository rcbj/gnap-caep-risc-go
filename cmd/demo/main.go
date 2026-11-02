// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rcbj/gnap-caep-risc-go"
)

func main() {
	public, given := publicURL(os.Args[1:])
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	demo := newDemo(public, given, port)
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: demo}
	fmt.Printf("gnap-caep-risc demo on port %s, configuration %s\n", port, demo.configPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func publicURL(argv []string) (string, bool) {
	public := strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	given := os.Getenv("PUBLIC_URL") != ""
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--public-url" && i+1 < len(argv) {
			i++
			public = strings.TrimRight(argv[i], "/")
			given = true
		}
	}
	return public, given
}

type sessionRecord struct {
	person *gnap.Person
	grant  *gnap.Grant
}

type demoServer struct {
	configPath  string
	publicDir   string
	publicURL   string
	publicGiven bool
	port        string
	secret      []byte
	mu          sync.Mutex
	client      *gnap.Client
	clientErr   string
	sessions    map[string]sessionRecord
	receiver    *gnap.SignalsReceiver
	latest      *gnap.Grant
	// receiverState and liveEvents are for GET /live-status: the receiver's state, and the type and
	// jti of each event it accepted. No tokens.
	receiverState string
	liveEvents    []map[string]string
}

func newDemo(public string, given bool, port string) *demoServer {
	secret := make([]byte, 32)
	if env := os.Getenv("SESSION_SECRET"); env != "" {
		secret = []byte(env)
	} else {
		_, _ = rand.Read(secret)
	}
	configPath := os.Getenv("GNAP_CONFIG")
	if configPath == "" {
		configPath = filepath.Join("demo", "gnap.json")
	}
	return &demoServer{
		configPath:    configPath,
		publicDir:     filepath.Join(filepath.Dir(configPath), "public"),
		publicURL:     public,
		publicGiven:   given,
		port:          port,
		secret:        secret,
		sessions:      map[string]sessionRecord{},
		receiverState: "not started (no sign-in yet)",
		liveEvents:    []map[string]string{},
	}
}

func (d *demoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Println(recovered)
			d.html(w, 500, "Error", "<h1>Something went wrong</h1><p>"+html.EscapeString(fmt.Sprint(recovered))+"</p><p><a href=\"/\">Home</a></p>", nil)
		}
	}()
	switch {
	case path == "/healthz" && r.Method == http.MethodGet:
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	case path == "/live-status" && r.Method == http.MethodGet:
		d.liveStatus(w, r)
	case path == "/styles.css" && r.Method == http.MethodGet:
		d.static(w, "styles.css", "text/css; charset=utf-8")
	case path == "/app.js" && r.Method == http.MethodGet:
		d.static(w, "app.js", "text/javascript; charset=utf-8")
	case path == "/" && r.Method == http.MethodGet:
		d.home(w, r)
	case path == "/login" && r.Method == http.MethodGet:
		d.login(w, r)
	case path == "/callback" && r.Method == http.MethodGet:
		d.callback(w, r)
	case path == "/logout" && r.Method == http.MethodPost:
		d.logout(w, r)
	case path == "/gnap/push" && r.Method == http.MethodPost:
		d.push(w, r)
	default:
		d.html(w, 404, "Not found", "<h1>Not found</h1>", nil)
	}
}

func (d *demoServer) static(w http.ResponseWriter, name, contentType string) {
	raw, err := os.ReadFile(filepath.Join(d.publicDir, name))
	if err != nil {
		d.html(w, 404, "Not found", "<h1>Not found</h1>", nil)
		return
	}
	w.Header().Set("content-type", contentType)
	w.Header().Set("cache-control", "max-age=300")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func (d *demoServer) html(w http.ResponseWriter, status int, title, body string, headers map[string][]string) {
	page := "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>" + html.EscapeString(title) + "</title>\n<link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n<main>\n" + body + "\n</main>\n</body>\n</html>\n"
	for name, values := range headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if w.Header().Get("content-type") == "" {
		w.Header().Set("content-type", "text/html; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

func (d *demoServer) readRaw() (map[string]any, error) {
	raw, err := os.ReadFile(d.configPath)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	display, _ := doc["display"].(map[string]any)
	displayURI := ""
	if display != nil {
		displayURI, _ = display["uri"].(string)
	}
	finish, _ := doc["finishUri"].(string)
	moved := redirectsFor(finish, displayURI, d.publicURL, d.publicGiven, d.port)
	if moved["finishUri"] != "" {
		doc["finishUri"] = moved["finishUri"]
	}
	if display != nil && moved["displayUri"] != "" {
		display["uri"] = moved["displayUri"]
		doc["display"] = display
	}
	return doc, nil
}

func (d *demoServer) gnap() (*gnap.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client, nil
	}
	doc, err := d.readRaw()
	if err != nil {
		d.clientErr = err.Error()
		return nil, err
	}
	cfg, err := gnap.Resolve(doc, filepath.Dir(d.configPath))
	if err != nil {
		d.clientErr = err.Error()
		return nil, err
	}
	d.client = gnap.New(cfg)
	d.clientErr = ""
	return d.client, nil
}

// liveStatus is JSON for scripts/live_iya_sts.py: whether this browser is signed in, as whom, the
// receiver's state, and the type and jti of every event received. It carries no tokens.
func (d *demoServer) liveStatus(w http.ResponseWriter, r *http.Request) {
	var subject any
	session := d.session(r)
	if session != nil && session.person != nil {
		person := session.person
		for _, value := range []string{person.PreferredUsername, person.Email, person.Name, person.Sub} {
			if value != "" {
				subject = value
				break
			}
		}
	}
	d.mu.Lock()
	events := append([]map[string]string{}, d.liveEvents...)
	state := d.receiverState
	d.mu.Unlock()
	raw, _ := json.Marshal(map[string]any{
		"signedIn": session != nil,
		"subject":  subject,
		"receiver": state,
		"events":   events,
	})
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

// trackedID is the id the receiver knows a session by: the grant id, or the subject.
func trackedID(grant *gnap.Grant) string {
	if grant == nil {
		return ""
	}
	if grant.GrantID != "" {
		return grant.GrantID
	}
	if grant.Subject != nil {
		return grant.Subject.Sub
	}
	return ""
}

// endTracked ends every cookie session whose grant the receiver tracks under one of ids. The cookie
// id and the tracked id differ, so this looks the sessions up by grant.
func (d *demoServer) endTracked(ids []string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	ended := 0
	for local, record := range d.sessions {
		known := trackedID(record.grant)
		for _, id := range ids {
			if known != "" && known == id {
				delete(d.sessions, local)
				ended++
				break
			}
		}
	}
	return ended
}

// remember records an accepted event for /live-status. A session-revoked event that ended no tracked
// session still ends this demo's one local session, if it has exactly one: the event can name the
// sign-on session by an id the grant did not carry.
func (d *demoServer) remember(event *gnap.SignalEvent) {
	d.mu.Lock()
	d.liveEvents = append(d.liveEvents, map[string]string{"type": event.Type, "jti": event.JTI})
	if len(d.liveEvents) > 100 {
		d.liveEvents = d.liveEvents[len(d.liveEvents)-100:]
	}
	var orphan *sessionRecord
	if event.Type == gnap.EventSessionRevoked && !event.Ended && len(d.sessions) == 1 {
		for local, record := range d.sessions {
			copied := record
			orphan = &copied
			delete(d.sessions, local)
		}
	}
	receiver := d.receiver
	d.mu.Unlock()
	if orphan != nil {
		fmt.Println("ssf: session-revoked matched no tracked session; ending this demo's one local session")
		if receiver != nil {
			receiver.Untrack(trackedID(orphan.grant))
		}
	}
}

func (d *demoServer) tryClient() *gnap.Client {
	client, err := d.gnap()
	if err != nil {
		return nil
	}
	return client
}

func (d *demoServer) home(w http.ResponseWriter, r *http.Request) {
	client := d.tryClient()
	if session := d.session(r); session != nil {
		who := session.person.Sub
		if session.person.Email != "" {
			who = session.person.Email
		} else if session.person.Name != "" {
			who = session.person.Name
		}
		d.html(w, 200, "Signed in", "<h1>Signed in</h1><p>"+html.EscapeString(who)+"</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>", nil)
		return
	}
	problem := ""
	link := ""
	if client == nil {
		d.mu.Lock()
		msg := d.clientErr
		d.mu.Unlock()
		if msg == "" {
			msg = "the key could not be read"
		}
		problem = "<p>The GNAP client is not configured yet: " + html.EscapeString(msg) + ". Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>"
	} else {
		link = "<p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>"
	}
	d.html(w, 200, "GNAP demo", "<h1>GNAP CAEP RISC demo</h1>"+problem+link, nil)
}

func (d *demoServer) login(w http.ResponseWriter, r *http.Request) {
	client, err := d.gnap()
	if err != nil {
		d.html(w, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>"+html.EscapeString(err.Error())+"</p><p><a href=\"/\">Start again</a></p>", nil)
		return
	}
	started, err := client.RequestGrant()
	if err != nil {
		d.html(w, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>"+html.EscapeString(err.Error())+"</p><p><a href=\"/\">Start again</a></p>", nil)
		return
	}
	if started.Grant != nil {
		d.place(w, started.Grant, "")
		return
	}
	pending := d.seal(map[string]any{"ids": []string{started.Pending.ID}})
	secure := ""
	if strings.HasPrefix(client.Config.FinishURI, "https:") {
		secure = "; Secure"
	}
	w.Header().Set("location", started.RedirectURL)
	w.Header().Set("set-cookie", "gpending="+pending+"; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax"+secure)
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(http.StatusFound)
}

func (d *demoServer) callback(w http.ResponseWriter, r *http.Request) {
	pending := d.unseal(cookieValue(r, "gpending"))
	var ids []string
	if pending != nil {
		if list, ok := pending["ids"].([]any); ok {
			for _, item := range list {
				if text, ok := item.(string); ok {
					ids = append(ids, text)
				}
			}
		}
	}
	flat := map[string]string{}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			flat[key] = values[0]
		}
	}
	clear := "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax"
	client, err := d.gnap()
	if err != nil {
		d.html(w, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>"+html.EscapeString(err.Error())+"</p><p><a href=\"/\">Start again</a></p>", map[string][]string{"set-cookie": {clear}})
		return
	}
	done, err := client.FinishRedirect(flat, ids)
	if err != nil || done.Grant.Subject == nil {
		if err == nil {
			err = fmt.Errorf("the grant has no subject")
		}
		fmt.Println("sign-in refused:", err)
		d.html(w, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>"+html.EscapeString(err.Error())+"</p><p><a href=\"/\">Start again</a></p>", map[string][]string{"set-cookie": {clear}})
		return
	}
	d.place(w, done.Grant, clear)
	d.watch(done.Grant, done.Grant.Subject)
}

func (d *demoServer) place(w http.ResponseWriter, grant *gnap.Grant, extra string) {
	local := randomToken()
	d.mu.Lock()
	d.sessions[local] = sessionRecord{person: grant.Subject, grant: grant}
	d.mu.Unlock()
	cookies := []string{"gsid=" + d.seal(map[string]any{"id": local}) + "; Path=/; HttpOnly; SameSite=Lax"}
	if extra != "" {
		cookies = append(cookies, extra)
	}
	w.Header().Set("location", "/")
	w.Header().Set("cache-control", "no-store")
	for _, cookie := range cookies {
		w.Header().Add("set-cookie", cookie)
	}
	w.WriteHeader(http.StatusSeeOther)
}

func (d *demoServer) logout(w http.ResponseWriter, r *http.Request) {
	opened := d.unseal(cookieValue(r, "gsid"))
	if opened != nil {
		id, _ := opened["id"].(string)
		d.mu.Lock()
		session, ok := d.sessions[id]
		delete(d.sessions, id)
		receiver := d.receiver
		d.mu.Unlock()
		if ok && receiver != nil && session.grant.GrantID != "" {
			receiver.Untrack(session.grant.GrantID)
		}
		if ok {
			if client, err := d.gnap(); err == nil {
				if err := client.Revoke(session.grant); err != nil {
					fmt.Println("revoke:", err)
				}
			}
		}
	}
	w.Header().Set("location", "/")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("set-cookie", "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
	w.WriteHeader(http.StatusSeeOther)
}

func (d *demoServer) push(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	client, err := d.gnap()
	if err != nil {
		writeErr(w, err)
		return
	}
	var body any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeErr(w, err)
			return
		}
	}
	done, err := client.FinishPush(body)
	if err != nil {
		writeErr(w, err)
		return
	}
	if done.Grant.Subject != nil {
		d.watch(done.Grant, done.Grant.Subject)
	}
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func writeErr(w http.ResponseWriter, err error) {
	raw, _ := json.Marshal(map[string]string{"error": err.Error()})
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(400)
	_, _ = w.Write(raw)
}

func (d *demoServer) signalsWanted() map[string]any {
	raw, err := os.ReadFile(d.configPath)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if doc["signals"] == false {
		return nil
	}
	ssf, _ := doc["ssf"].(map[string]any)
	if ssf == nil || ssf["transmitter"] == nil || ssf["transmitter"] == "" {
		return nil
	}
	return ssf
}

func (d *demoServer) watch(grant *gnap.Grant, person *gnap.Person) {
	d.mu.Lock()
	d.latest = grant
	if d.receiver != nil {
		receiver := d.receiver
		d.mu.Unlock()
		receiver.Track(tracked(grant, person))
		return
	}
	d.mu.Unlock()
	wanted := d.signalsWanted()
	if wanted == nil {
		d.mu.Lock()
		d.receiverState = "not configured (signals are off, or no ssf.transmitter)"
		d.mu.Unlock()
		return
	}
	interval := 5000
	switch n := wanted["pollIntervalMs"].(type) {
	case float64:
		if n != 0 {
			interval = int(n)
		}
	case json.Number:
		if f, err := n.Float64(); err == nil && f != 0 {
			interval = int(f)
		}
	}
	transmitter, _ := wanted["transmitter"].(string)
	client, err := d.gnap()
	if err != nil {
		return
	}
	tlsOpt, err := client.TLS()
	if err != nil {
		fmt.Println("ssf: not started:", err)
		return
	}
	receiver, err := gnap.NewSignalsReceiver(transmitter, func(ids []string, event *gnap.SignalEvent) {
		d.endTracked(ids)
	}, gnap.ReceiverOpt{
		TLS: tlsOpt,
		Headers: func(request gnap.SSFRequest) map[string]string {
			d.mu.Lock()
			latest := d.latest
			d.mu.Unlock()
			if latest == nil {
				return map[string]string{}
			}
			current, err := d.gnap()
			if err != nil {
				return map[string]string{}
			}
			var body *string
			if request.Body != "" {
				text := request.Body
				body = &text
			}
			headers, err := current.AuthorizationHeaders(latest, request.Method, request.URL, body)
			if err != nil {
				return map[string]string{}
			}
			return headers
		},
		PollIntervalMs: interval,
	})
	if err != nil {
		fmt.Println("ssf: not started:", err)
		return
	}
	receiver.On("*", d.remember)
	if err := receiver.Start(); err != nil {
		fmt.Println("ssf: not started:", err)
		d.mu.Lock()
		d.receiverState = "not running: " + err.Error()
		d.mu.Unlock()
		return
	}
	receiver.Track(tracked(grant, person))
	d.mu.Lock()
	d.receiver = receiver
	d.receiverState = fmt.Sprintf("polling stream %v at %s", receiver.Stream["stream_id"], transmitter)
	d.mu.Unlock()
}

func tracked(grant *gnap.Grant, person *gnap.Person) gnap.TrackedSession {
	local := grant.GrantID
	if local == "" && person != nil {
		local = person.Sub
	}
	var expires *float64
	if grant.ExpiresAt != nil {
		value := *grant.ExpiresAt
		expires = &value
	}
	return gnap.TrackedFromPerson(local, person, expires)
}

func (d *demoServer) session(r *http.Request) *sessionRecord {
	opened := d.unseal(cookieValue(r, "gsid"))
	if opened == nil {
		return nil
	}
	id, _ := opened["id"].(string)
	d.mu.Lock()
	defer d.mu.Unlock()
	record, ok := d.sessions[id]
	if !ok {
		return nil
	}
	return &record
}

func cookieValue(r *http.Request, name string) string {
	for _, part := range strings.Split(r.Header.Get("cookie"), ";") {
		item := strings.TrimSpace(part)
		if strings.HasPrefix(item, name+"=") {
			return item[len(name)+1:]
		}
	}
	return ""
}

func (d *demoServer) seal(payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, d.secret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + fmt.Sprintf("%x", mac.Sum(nil))
}

func (d *demoServer) unseal(token string) map[string]any {
	dot := strings.LastIndex(token, ".")
	if token == "" || dot <= 0 {
		return nil
	}
	raw := token[:dot]
	macText := token[dot+1:]
	mac := hmac.New(sha256.New, d.secret)
	_, _ = mac.Write([]byte(raw))
	if !hmac.Equal([]byte(fmt.Sprintf("%x", mac.Sum(nil))), []byte(macText)) {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(decoded, &doc); err != nil {
		return nil
	}
	return doc
}

func randomToken() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func redirectsFor(finishURI, displayURI, publicURL string, given bool, port string) map[string]string {
	out := map[string]string{}
	if finishURI != "" {
		out["finishUri"] = finishURI
	}
	if displayURI != "" {
		out["displayUri"] = displayURI
	}
	if given && publicURL != "" {
		base, err := url.Parse(publicURL + "/")
		if err != nil {
			return out
		}
		move := func(value string) string {
			if value == "" {
				return value
			}
			next, err := url.Parse(value)
			if err != nil {
				return value
			}
			path := next.Path
			if path == "" {
				path = "/"
			}
			return (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: path, RawQuery: next.RawQuery, Fragment: next.Fragment}).String()
		}
		if finishURI != "" {
			out["finishUri"] = move(finishURI)
		}
		if displayURI != "" {
			out["displayUri"] = move(displayURI)
		}
		return out
	}
	if port != "" {
		if finishURI != "" {
			out["finishUri"] = onPort(finishURI, port)
		}
		if displayURI != "" {
			out["displayUri"] = onPort(displayURI, port)
		}
	}
	return out
}

func onPort(raw, port string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return raw
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return raw
	}
	shown := parsed.Hostname()
	if strings.Contains(shown, ":") && !strings.HasPrefix(shown, "[") {
		shown = "[" + shown + "]"
	}
	parsed.Host = shown + ":" + port
	return parsed.String()
}
