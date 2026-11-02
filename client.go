// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/rand"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var frontChannel = []string{"access_token", "id_token", "token", "value", "continue", "refresh_token"}

// Continuation is a GNAP continue or manage handle. The token is key-bound.
type Continuation struct {
	URI         string
	AccessToken string
	Wait        *float64
}

// Grant is an access token and the subject it was issued for.
type Grant struct {
	AccessToken  string
	Bearer       bool
	Access       any
	ExpiresIn    *float64
	ExpiresAt    *float64
	Manage       *Continuation
	Continuation *Continuation
	InstanceID   string
	Subject      *Person
	GrantID      string
}

// Pending is a grant whose browser interaction has not finished.
type Pending struct {
	ID                string
	ClientNonce       string
	ServerNonce       string
	HashMethod        string
	Continuation      *Continuation
	ContinueNotBefore float64
	GrantEndpoint     string
	CreatedAt         float64
	Context           any
	InstanceID        string
	ExpectedSub       string
}

// GrantResult is either a redirect the browser must follow or a grant that needed no interaction.
type GrantResult struct {
	RedirectURL string
	Pending     *Pending
	Grant       *Grant
}

// Finished is a grant completed from a redirect or a push.
type Finished struct {
	Grant   *Grant
	Context any
}

// Client is a server-side GNAP client. The private key stays in this process.
type Client struct {
	Config     *Config
	mu         sync.Mutex
	metadata   *GrantServer
	instanceID string
	subIDs     []string
	assertions []string
	jwks       []map[string]any
	pending    map[string]*Pending
	order      []string
	used       map[string]struct{}
	usedOrder  []string
}

// FromFile loads gnap.json and returns a client.
func FromFile(path string) (*Client, error) {
	cfg, err := ReadConfigFile(path)
	if err != nil {
		return nil, err
	}
	return New(cfg), nil
}

// New returns a client for an already resolved configuration.
func New(cfg *Config) *Client {
	return &Client{
		Config:     cfg,
		subIDs:     append([]string{}, cfg.SubIDFormats...),
		assertions: append([]string{}, cfg.AssertionFormats...),
		pending:    map[string]*Pending{},
		used:       map[string]struct{}{},
	}
}

// TLS is the back-channel trust material, including the mutual TLS chain when that proof is in use.
func (c *Client) TLS() (TLSOpt, error) {
	opt := TLSOpt{CA: c.Config.TLSCA}
	key := c.Config.Key
	if key != nil && key.Proof == "mtls" && (key.ChainPEM != "" || key.CertPEM != "") {
		opt.Cert = key.ChainPEM
		if opt.Cert == "" {
			opt.Cert = key.CertPEM
		}
		pemText, err := key.PrivatePEM()
		if err != nil {
			return opt, failCause("config", err.Error(), err)
		}
		opt.Key = pemText
	}
	return opt, nil
}

func (c *Client) discover() error {
	c.mu.Lock()
	if c.metadata != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	tlsOpt, err := c.TLS()
	if err != nil {
		return err
	}
	meta, err := DiscoverGrantServer(c.Config.GrantEndpoint, tlsOpt)
	if err != nil {
		return err
	}
	if len(meta.KeyProofs) > 0 && !containsString(meta.KeyProofs, c.Config.Key.Proof) {
		return fmtFail("discovery", "the grant server does not accept the %s key proof", c.Config.Key.Proof)
	}
	if len(meta.InteractionFinish) > 0 && c.Config.FinishURI != "" && !containsString(meta.InteractionFinish, c.Config.FinishMethod) {
		return fmtFail("discovery", "the grant server does not accept a %s interaction finish", c.Config.FinishMethod)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.metadata != nil {
		return nil
	}
	if len(meta.SubIDFormats) > 0 {
		c.subIDs = filterListed(c.subIDs, meta.SubIDFormats)
	}
	if len(meta.AssertionFormats) > 0 {
		c.assertions = filterListed(c.assertions, meta.AssertionFormats)
	}
	c.metadata = meta
	return nil
}

func filterListed(have, allowed []string) []string {
	var out []string
	for _, item := range have {
		if containsString(allowed, item) {
			out = append(out, item)
		}
	}
	return out
}

// RequestGrant asks for the configured access and returns the redirect the browser should open.
func (c *Client) RequestGrant() (*GrantResult, error) {
	return c.RequestGrantAccess(nil, "", nil)
}

// RequestGrantAccess asks for access, or the configured rights when access is nil. expectedSub is optional.
func (c *Client) RequestGrantAccess(access []any, expectedSub string, user any) (*GrantResult, error) {
	if err := c.discover(); err != nil {
		return nil, err
	}
	rights := access
	if rights == nil {
		rights = c.Config.Access
	}
	if len(rights) == 0 {
		return nil, fail("config", "access is required")
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, failCause("protocol", err.Error(), err)
	}
	clientNonce := B64URL(buf)
	member, err := c.clientMember()
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"access_token": map[string]any{"access": rights},
		"client":       member,
	}
	if c.Config.FinishURI != "" {
		body["interact"] = map[string]any{
			"start": c.Config.InteractionStart,
			"finish": map[string]any{
				"method": c.Config.FinishMethod,
				"uri":    c.Config.FinishURI,
				"nonce":  clientNonce,
			},
		}
	}
	c.mu.Lock()
	subIDs := append([]string{}, c.subIDs...)
	assertions := append([]string{}, c.assertions...)
	c.mu.Unlock()
	if len(subIDs) > 0 || len(assertions) > 0 {
		subject := map[string]any{}
		if len(subIDs) > 0 {
			subject["sub_id_formats"] = subIDs
		}
		if len(assertions) > 0 {
			subject["assertion_formats"] = assertions
		}
		body["subject"] = subject
	}
	if user != nil {
		body["user"] = user
	}
	answer, err := c.signedJSON("POST", c.Config.GrantEndpoint, body, "")
	if err != nil {
		return nil, err
	}
	c.rememberInstance(answer)
	doc, _ := AsMap(answer)
	if doc != nil && doc["interact"] != nil {
		redirect, err := c.redirectOf(doc)
		if err != nil {
			return nil, err
		}
		pending, err := c.rememberPending(doc, clientNonce, nil, expectedSub)
		if err != nil {
			return nil, err
		}
		return &GrantResult{RedirectURL: redirect, Pending: pending}, nil
	}
	if hasToken(answer) {
		grant, err := c.grantFrom(answer, nil)
		if err != nil {
			return nil, err
		}
		if err := expectSub(grant, expectedSub); err != nil {
			return nil, err
		}
		return &GrantResult{Grant: grant}, nil
	}
	return nil, fail("protocol", "the grant response has neither an interaction nor an access token")
}

// FinishRedirect completes a redirect interaction. allowedIDs are the pending ids this browser was given.
func (c *Client) FinishRedirect(query any, allowedIDs []string) (*Finished, error) {
	names, err := queryNames(query)
	if err != nil {
		return nil, err
	}
	var injected []string
	for _, name := range frontChannel {
		if _, ok := names[name]; ok {
			injected = append(injected, name)
		}
	}
	if len(injected) > 0 {
		return nil, fail("validation", "the finish redirect carries "+strings.Join(injected, ", ")+"; GNAP does not send tokens through the browser")
	}
	for name, values := range names {
		if len(values) > 1 {
			return nil, fail("validation", "the finish redirect repeats \""+name+"\"")
		}
	}
	digest := firstValue(names["hash"])
	interactRef := firstValue(names["interact_ref"])
	if digest == "" || interactRef == "" {
		if code := firstValue(names["error"]); code != "" {
			msg := firstValue(names["error_description"])
			if msg == "" {
				msg = code
			}
			return nil, &Error{Code: "protocol", Msg: msg, Gnap: code}
		}
		return nil, fail("validation", "the finish redirect has no hash or interact_ref")
	}
	pending, err := c.match(digest, interactRef, allowedIDs, true)
	if err != nil {
		return nil, err
	}
	return c.finish(pending, interactRef, digest)
}

// FinishPush completes a back-channel interaction finish.
func (c *Client) FinishPush(body any) (*Finished, error) {
	doc, ok := AsMap(body)
	if !ok {
		return nil, fail("validation", "a push finish is a JSON object")
	}
	digest, digestOK := doc["hash"].(string)
	interactRef, refOK := doc["interact_ref"].(string)
	if !digestOK || !refOK {
		if code, isStr := doc["error"].(string); isStr {
			return nil, &Error{Code: "protocol", Msg: code, Gnap: code}
		}
		return nil, fail("validation", "a push finish needs hash and interact_ref")
	}
	pending, err := c.match(digest, interactRef, nil, false)
	if err != nil {
		return nil, err
	}
	return c.finish(pending, interactRef, digest)
}

// AuthorizationHeaders are the key proof for one request that carries this grant's access token.
func (c *Client) AuthorizationHeaders(grant *Grant, method, rawURL string, body *string) (map[string]string, error) {
	return c.proofHeaders(method, rawURL, body, grant.AccessToken, nil)
}

// Call sends a key-bound request.
func (c *Client) Call(grant *Grant, rawURL, method string, headers map[string]string, body *string) (*Answer, error) {
	if method == "" {
		method = "GET"
	}
	proof, err := c.AuthorizationHeaders(grant, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	merged := map[string]string{}
	for name, value := range headers {
		merged[name] = value
	}
	for name, value := range proof {
		merged[name] = value
	}
	tlsOpt, err := c.TLS()
	if err != nil {
		return nil, err
	}
	return Send(rawURL, method, merged, body, tlsOpt, "protocol")
}

// Rotate asks the authorization server for a new access token.
func (c *Client) Rotate(grant *Grant) (*Grant, error) {
	if grant.Manage == nil {
		return nil, fail("protocol", "this access token has no manage URI")
	}
	if err := c.checkSameOrigin(grant.Manage.URI, "manage.uri"); err != nil {
		return nil, err
	}
	answer, err := c.signedJSON("POST", grant.Manage.URI, nil, grant.Manage.AccessToken)
	if err != nil {
		return nil, err
	}
	if !hasToken(answer) {
		return nil, fail("protocol", "the rotation returned no access token")
	}
	next, err := c.grantFrom(answer, &previousGrant{previous: grant})
	if err != nil {
		return nil, err
	}
	if !grant.Bearer && next.Bearer {
		return nil, fail("validation", "rotating a key-bound token returned a bearer token")
	}
	return next, nil
}

// Revoke deletes the grant.
func (c *Client) Revoke(grant *Grant) error {
	if grant.Continuation == nil {
		return fail("protocol", "this grant has no continuation, so it cannot be revoked")
	}
	if err := c.checkSameOrigin(grant.Continuation.URI, "continue.uri"); err != nil {
		return err
	}
	_, err := c.signedJSON("DELETE", grant.Continuation.URI, nil, grant.Continuation.AccessToken)
	return err
}

// EnsureFresh rotates when the access token expires within 60 seconds. now is milliseconds.
func (c *Client) EnsureFresh(grant *Grant) (*Grant, error) {
	now := float64(time.Now().UnixMilli())
	if grant.ExpiresAt == nil || *grant.ExpiresAt-now > 60000 {
		return grant, nil
	}
	return c.Rotate(grant)
}

func (c *Client) clientMember() (any, error) {
	c.mu.Lock()
	instance := c.instanceID
	c.mu.Unlock()
	if c.Config.UseInstanceID && instance != "" {
		return instance, nil
	}
	key, err := PublicKeyObject(c.Config.Key)
	if err != nil {
		return nil, err
	}
	member := map[string]any{"key": key}
	if c.Config.Display != nil {
		display := map[string]any{}
		if c.Config.Display.Name != "" {
			display["name"] = c.Config.Display.Name
		}
		if c.Config.Display.URI != "" {
			display["uri"] = c.Config.Display.URI
		}
		if len(display) > 0 {
			member["display"] = display
		}
	}
	if c.Config.ClassID != "" {
		member["class_id"] = c.Config.ClassID
	}
	return member, nil
}

func (c *Client) rememberInstance(answer any) {
	if !c.Config.UseInstanceID {
		return
	}
	doc, ok := AsMap(answer)
	if !ok {
		return
	}
	if id, ok := doc["instance_id"].(string); ok && id != "" {
		c.mu.Lock()
		c.instanceID = id
		c.mu.Unlock()
	}
}

func (c *Client) redirectOf(answer map[string]any) (string, error) {
	interact, _ := AsMap(answer["interact"])
	redirect := str(interact["redirect"])
	if redirect == "" {
		return "", fail("protocol", "the interaction is not a redirect")
	}
	parts, err := url.Parse(redirect)
	if err != nil || parts.Scheme == "" || parts.Hostname() == "" {
		return "", fail("protocol", "interact.redirect is not a URL: "+redirect)
	}
	if parts.Scheme != "https" && !(parts.Scheme == "http" && (c.Config.AllowInsecure || IsLoopback(redirect))) {
		return "", fail("validation", "interact.redirect must use https: "+redirect)
	}
	return redirect, nil
}

func (c *Client) rememberPending(answer map[string]any, clientNonce string, context any, expectedSub string) (*Pending, error) {
	interact, _ := AsMap(answer["interact"])
	finish, ok := interact["finish"].(string)
	if !ok || finish == "" {
		return nil, fail("protocol", "the grant response has no interaction finish nonce")
	}
	cont, err := c.continuation(answer["continue"], "continue")
	if err != nil {
		return nil, err
	}
	wait := 0.0
	if cont.Wait != nil {
		wait = *cont.Wait
	}
	now := float64(time.Now().UnixMilli())
	pending := &Pending{
		ID:                clientNonce,
		ClientNonce:       clientNonce,
		ServerNonce:       finish,
		HashMethod:        "sha-256",
		Continuation:      cont,
		ContinueNotBefore: now + wait*1000,
		GrantEndpoint:     c.Config.GrantEndpoint,
		CreatedAt:         now,
		Context:           context,
		ExpectedSub:       expectedSub,
	}
	c.mu.Lock()
	pending.InstanceID = c.instanceID
	c.sweepLocked(now)
	c.pending[pending.ID] = pending
	c.order = append(c.order, pending.ID)
	for len(c.pending) > 1000 && len(c.order) > 0 {
		delete(c.pending, c.order[0])
		c.order = c.order[1:]
	}
	c.mu.Unlock()
	return pending, nil
}

func (c *Client) sweepLocked(now float64) {
	cutoff := now - c.Config.TransactionTTLSec*1000
	var kept []string
	for _, id := range c.order {
		pending := c.pending[id]
		if pending == nil {
			continue
		}
		if pending.CreatedAt < cutoff {
			delete(c.pending, id)
			continue
		}
		kept = append(kept, id)
	}
	c.order = kept
}

func (c *Client) match(digest, interactRef string, allowed []string, useAllow bool) (*Pending, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.used[digest]; seen {
		return nil, fail("validation", "this interaction finish was already used")
	}
	now := float64(time.Now().UnixMilli())
	for _, pending := range c.pending {
		if useAllow && !containsString(allowed, pending.ID) {
			continue
		}
		expected := InteractionHash(pending.ClientNonce, pending.ServerNonce, interactRef, pending.GrantEndpoint)
		if !HashEqual(digest, expected) {
			continue
		}
		if now-pending.CreatedAt > c.Config.TransactionTTLSec*1000 {
			delete(c.pending, pending.ID)
			return nil, &Error{Code: "validation", Msg: "the approval took too long; start again", Context: pending.Context}
		}
		return pending, nil
	}
	if useAllow {
		return nil, fail("validation", "this finish is not a sign-in this browser started")
	}
	return nil, fail("validation", "the interaction hash matches no grant in progress")
}

func (c *Client) finish(pending *Pending, interactRef, digest string) (*Finished, error) {
	c.mu.Lock()
	delete(c.pending, pending.ID)
	c.used[digest] = struct{}{}
	c.usedOrder = append(c.usedOrder, digest)
	if len(c.usedOrder) > 1000 {
		delete(c.used, c.usedOrder[0])
		c.usedOrder = c.usedOrder[1:]
	}
	c.mu.Unlock()
	due := pending.ContinueNotBefore - float64(time.Now().UnixMilli())
	if due > 0 {
		capMs := c.Config.MaxWaitSec * 1000
		if due > capMs {
			due = capMs
		}
		time.Sleep(time.Duration(due) * time.Millisecond)
	}
	answer, err := c.continueGrant(pending.Continuation, map[string]any{"interact_ref": interactRef})
	if err != nil {
		return nil, withContext(err, pending.Context)
	}
	if !hasToken(answer) {
		return nil, &Error{Code: "protocol", Msg: "the resource owner did not approve the grant", Gnap: "user_denied", Context: pending.Context}
	}
	grant, err := c.grantFrom(answer, &previousGrant{previousContinue: pending.Continuation})
	if err != nil {
		return nil, withContext(err, pending.Context)
	}
	if err := expectSub(grant, pending.ExpectedSub); err != nil {
		return nil, withContext(err, pending.Context)
	}
	return &Finished{Grant: grant, Context: pending.Context}, nil
}

func (c *Client) continueGrant(cont *Continuation, body any) (any, error) {
	current := cont
	waited := 0.0
	immediate := 0
	for {
		answer, err := c.signedJSON("POST", current.URI, body, current.AccessToken)
		if err == nil {
			return answer, nil
		}
		ge := asError(err)
		if ge == nil || ge.Gnap != "too_fast" {
			return nil, err
		}
		if ge.Cont != nil {
			if err := c.checkSameOrigin(ge.Cont.URI, "continue.uri"); err != nil {
				return nil, err
			}
			current = ge.Cont
		}
		wait := 0.0
		if current.Wait != nil && *current.Wait > 0 {
			wait = *current.Wait
		}
		if wait == 0 {
			immediate++
			if immediate > 2 {
				return nil, ge
			}
			continue
		}
		if waited+wait > c.Config.MaxWaitSec {
			return nil, ge
		}
		time.Sleep(time.Duration(wait * float64(time.Second)))
		waited += wait
	}
}

func (c *Client) signedJSON(method, rawURL string, body any, token string) (any, error) {
	if err := c.checkSameOrigin(rawURL, "the request URL"); err != nil {
		return nil, err
	}
	var text *string
	if body != nil {
		dumped, err := Dump(body)
		if err != nil {
			return nil, failCause("protocol", err.Error(), err)
		}
		text = &dumped
	}
	extra := map[string]string{}
	if text != nil {
		extra["content-type"] = "application/json"
	}
	headers, err := c.proofHeaders(method, rawURL, text, token, extra)
	if err != nil {
		return nil, err
	}
	headers["accept"] = "application/json"
	tlsOpt, err := c.TLS()
	if err != nil {
		return nil, err
	}
	answer, err := Send(rawURL, method, headers, text, tlsOpt, "protocol")
	if err != nil {
		return nil, err
	}
	return c.read(answer)
}

func (c *Client) proofHeaders(method, rawURL string, body *string, token string, extra map[string]string) (map[string]string, error) {
	headers := map[string]string{}
	for name, value := range extra {
		headers[name] = value
	}
	if token != "" {
		headers["authorization"] = "GNAP " + token
	}
	switch c.Config.Key.Proof {
	case "httpsig":
		signed, err := SignRequest(c.Config.Key, method, rawURL, headers, body)
		if err != nil {
			return nil, err
		}
		for name, value := range signed {
			headers[name] = value
		}
	case "jwsd":
		detached, err := DetachedJWS(c.Config.Key, method, rawURL, body, token)
		if err != nil {
			return nil, err
		}
		headers["detached-jws"] = detached
	}
	return headers, nil
}

func (c *Client) read(answer *Answer) (any, error) {
	if answer.Status == 204 || answer.Body == "" {
		if answer.Status >= 400 {
			return nil, fmtFail("protocol", "the authorization server answered %d", answer.Status)
		}
		return nil, nil
	}
	parsed, err := DecodeJSON(answer.Body)
	if err != nil {
		return nil, failCause("protocol", "the authorization server answered "+strconv.Itoa(answer.Status)+" with a body that is not JSON", err)
	}
	if answer.Status >= 200 && answer.Status < 300 {
		return parsed, nil
	}
	doc, _ := AsMap(parsed)
	code := ""
	if text, ok := doc["error"].(string); ok {
		code = text
	}
	var cont *Continuation
	if raw, ok := AsMap(doc["continue"]); ok {
		token := ""
		if access, ok := AsMap(raw["access_token"]); ok {
			token = str(access["value"])
		}
		uri := str(raw["uri"])
		if uri != "" && token != "" {
			cont = &Continuation{URI: uri, AccessToken: token}
			if n, ok := AsFloat(raw["wait"]); ok {
				cont.Wait = &n
			}
		}
	}
	msg := ""
	if text, ok := doc["error_description"].(string); ok {
		msg = text
	}
	if msg == "" {
		msg = code
	}
	if msg == "" {
		msg = "the authorization server answered " + strconv.Itoa(answer.Status)
	}
	return nil, &Error{Code: "protocol", Msg: msg, Gnap: code, Cont: cont}
}

func hasToken(answer any) bool {
	doc, ok := AsMap(answer)
	if !ok {
		return false
	}
	value, present := doc["access_token"]
	if !present || value == nil {
		return false
	}
	if list, ok := value.([]any); ok {
		return len(list) > 0
	}
	if text, ok := value.(string); ok {
		return text != ""
	}
	return true
}

type previousGrant struct {
	previous         *Grant
	previousContinue *Continuation
}

func (c *Client) grantFrom(answer any, previous *previousGrant) (*Grant, error) {
	doc, _ := AsMap(answer)
	token := doc["access_token"]
	if list, ok := AsList(token); ok {
		if len(list) == 0 {
			token = nil
		} else {
			token = list[0]
		}
	}
	tokenDoc, ok := AsMap(token)
	if !ok {
		return nil, fail("protocol", "the access token is not an object")
	}
	value := str(tokenDoc["value"])
	if value == "" {
		return nil, fail("protocol", "the access token has no value")
	}
	var flags []string
	if list, ok := AsList(tokenDoc["flags"]); ok {
		for _, item := range list {
			flags = append(flags, toString(item))
		}
	}
	bearer := containsString(flags, "bearer")
	if bearer && c.Config.RequireBoundTokens {
		return nil, fail("validation", "the authorization server issued a bearer token, and this client requires a key-bound one")
	}
	c.rememberInstance(answer)
	var manage *Continuation
	if raw, ok := AsMap(tokenDoc["manage"]); ok {
		manageToken := ""
		if access, ok := AsMap(raw["access_token"]); ok {
			manageToken = str(access["value"])
		}
		uri := str(raw["uri"])
		if uri == "" || manageToken == "" {
			return nil, fail("protocol", "the access token manage object is not usable")
		}
		if err := c.checkSameOrigin(uri, "manage.uri"); err != nil {
			return nil, err
		}
		manage = &Continuation{URI: uri, AccessToken: manageToken}
	} else if previous != nil && previous.previous != nil {
		manage = previous.previous.Manage
	}
	var cont *Continuation
	if doc["continue"] != nil {
		next, err := c.continuation(doc["continue"], "continue")
		if err != nil {
			return nil, err
		}
		cont = next
	} else if previous != nil && previous.previousContinue != nil {
		cont = previous.previousContinue
	} else if previous != nil && previous.previous != nil {
		cont = previous.previous.Continuation
	}
	c.mu.Lock()
	instance := c.instanceID
	c.mu.Unlock()
	var audiences []string
	if instance != "" {
		audiences = append(audiences, instance)
	}
	if c.Config.Application != "" {
		audiences = append(audiences, c.Config.Application)
	}
	var subject *Person
	if doc["subject"] != nil {
		person, err := PersonFrom(doc["subject"], IDCheck{
			Issuer:    c.Config.IDTokenIssuer,
			Audiences: audiences,
			Skew:      c.Config.ClockToleranceSec,
			Keys:      c.idTokenKeys,
		})
		if err != nil {
			return nil, err
		}
		subject = person
	} else if previous != nil && previous.previous != nil {
		subject = previous.previous.Subject
	}
	var expiresIn *float64
	if n, ok := AsFloat(tokenDoc["expires_in"]); ok {
		expiresIn = &n
	}
	var expiresAt *float64
	if expiresIn != nil {
		at := float64(time.Now().UnixMilli()) + *expiresIn*1000
		expiresAt = &at
	}
	grantURI := ""
	if cont != nil {
		grantURI = cont.URI
	}
	return &Grant{
		AccessToken:  value,
		Bearer:       bearer,
		Access:       tokenDoc["access"],
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		Manage:       manage,
		Continuation: cont,
		InstanceID:   instance,
		Subject:      subject,
		GrantID:      grantID(grantURI),
	}, nil
}

func expectSub(grant *Grant, expected string) error {
	if expected != "" && grant.Subject != nil && grant.Subject.Sub != expected {
		return fail("validation", "the grant was approved by somebody other than the account that was asked for")
	}
	return nil
}

func (c *Client) continuation(raw any, what string) (*Continuation, error) {
	doc, ok := AsMap(raw)
	if !ok {
		return nil, fail("protocol", "the response has no "+what+" object")
	}
	token := ""
	if access, ok := AsMap(doc["access_token"]); ok {
		token = str(access["value"])
	}
	uri := str(doc["uri"])
	if uri == "" || token == "" {
		return nil, fail("protocol", "the response has no usable "+what+" object")
	}
	if err := c.checkSameOrigin(uri, what+".uri"); err != nil {
		return nil, err
	}
	var wait *float64
	if _, present := doc["wait"]; present && doc["wait"] != nil {
		n, ok := AsFloat(doc["wait"])
		if !ok || n < 0 {
			return nil, fail("protocol", what+".wait is not a number of seconds")
		}
		wait = &n
	}
	return &Continuation{URI: uri, AccessToken: token, Wait: wait}, nil
}

func (c *Client) checkSameOrigin(uri, what string) error {
	parts, err := url.Parse(uri)
	if err != nil || (parts.Scheme != "http" && parts.Scheme != "https") || parts.Host == "" {
		return fail("validation", what+" is not a URL: "+uri)
	}
	if parts.Scheme != "https" && !c.Config.AllowInsecure {
		return fail("validation", what+" must use https: "+uri)
	}
	got, err := Origin(uri)
	if err != nil {
		return fail("validation", what+" is not a URL: "+uri)
	}
	want, err := Origin(c.Config.GrantEndpoint)
	if err != nil {
		return err
	}
	if got != want {
		return fail("validation", what+" "+uri+" is not on the grant endpoint's origin")
	}
	return nil
}

func (c *Client) idTokenKeys() ([]map[string]any, error) {
	c.mu.Lock()
	if c.jwks != nil {
		keys := c.jwks
		c.mu.Unlock()
		return keys, nil
	}
	c.mu.Unlock()
	tlsOpt, err := c.TLS()
	if err != nil {
		return nil, err
	}
	meta, err := DiscoverOpenID(c.Config.IDTokenIssuer, tlsOpt)
	if err != nil {
		return nil, err
	}
	answer, err := Send(meta.JWKSURI, "GET", map[string]string{"accept": "application/json"}, nil, tlsOpt, "discovery")
	if err != nil {
		return nil, err
	}
	parsed, err := DecodeJSON(answer.Body)
	if err != nil {
		return nil, failCause("discovery", "the issuer JWKS is not JSON", err)
	}
	doc, _ := AsMap(parsed)
	list, listOK := AsList(doc["keys"])
	if answer.Status != 200 || !listOK {
		return nil, fmtFail("discovery", "the issuer JWKS answered %d", answer.Status)
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		one, ok := AsMap(item)
		if !ok {
			return nil, fmtFail("discovery", "the issuer JWKS answered %d", answer.Status)
		}
		out = append(out, one)
	}
	c.mu.Lock()
	c.jwks = out
	c.mu.Unlock()
	return out, nil
}

func grantID(uri string) string {
	if uri == "" {
		return ""
	}
	parts, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	chunks := strings.Split(strings.Trim(parts.Path, "/"), "/")
	if len(chunks) == 0 || chunks[0] == "" {
		return ""
	}
	last := chunks[len(chunks)-1]
	decoded, err := url.PathUnescape(last)
	if err != nil {
		return last
	}
	return decoded
}

func withContext(err error, context any) error {
	if ge := asError(err); ge != nil && context != nil {
		ge.Context = context
	}
	return err
}

func queryNames(query any) (map[string][]string, error) {
	switch value := query.(type) {
	case string:
		text := value
		if strings.Contains(text, "://") || strings.HasPrefix(text, "/") {
			parsed, err := url.Parse(text)
			if err != nil {
				return nil, fail("validation", "the finish redirect could not be read")
			}
			text = parsed.RawQuery
		} else if strings.HasPrefix(text, "?") || strings.HasPrefix(text, "#") {
			text = text[1:]
		}
		parsed, err := url.ParseQuery(text)
		if err != nil {
			return nil, fail("validation", "the finish redirect could not be read")
		}
		out := map[string][]string{}
		for key, items := range parsed {
			out[key] = append([]string{}, items...)
		}
		return out, nil
	case map[string]string:
		out := map[string][]string{}
		for key, item := range value {
			out[key] = []string{item}
		}
		return out, nil
	case map[string][]string:
		out := map[string][]string{}
		for key, items := range value {
			for _, item := range items {
				out[key] = append(out[key], item)
			}
		}
		return out, nil
	case map[string]any:
		out := map[string][]string{}
		for key, item := range value {
			switch one := item.(type) {
			case string:
				out[key] = []string{one}
			case []string:
				out[key] = append([]string{}, one...)
			case []any:
				for _, piece := range one {
					if text, ok := piece.(string); ok {
						out[key] = append(out[key], text)
					}
				}
			}
		}
		return out, nil
	default:
		return nil, fail("validation", "the finish redirect could not be read")
	}
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
