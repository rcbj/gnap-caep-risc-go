// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

// CAEP, RISC, and SSF event type prefixes.
const (
	CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
	RISC = "https://schemas.openid.net/secevent/risc/event-type/"
	SSF  = "https://schemas.openid.net/secevent/ssf/event-type/"
)

// Shared Signals event types this receiver understands.
const (
	EventSessionRevoked                  = CAEP + "session-revoked"
	EventTokenClaimsChange               = CAEP + "token-claims-change"
	EventCredentialChange                = CAEP + "credential-change"
	EventAssuranceLevelChange            = CAEP + "assurance-level-change"
	EventDeviceComplianceChange          = CAEP + "device-compliance-change"
	EventSessionEstablished              = CAEP + "session-established"
	EventSessionPresented                = CAEP + "session-presented"
	EventRiskLevelChange                 = CAEP + "risk-level-change"
	EventAccountCredentialChangeRequired = RISC + "account-credential-change-required"
	EventAccountPurged                   = RISC + "account-purged"
	EventAccountDisabled                 = RISC + "account-disabled"
	EventAccountEnabled                  = RISC + "account-enabled"
	EventIdentifierChanged               = RISC + "identifier-changed"
	EventIdentifierRecycled              = RISC + "identifier-recycled"
	EventCredentialCompromise            = RISC + "credential-compromise"
	EventOptIn                           = RISC + "opt-in"
	EventOptOutInitiated                 = RISC + "opt-out-initiated"
	EventOptOutCancelled                 = RISC + "opt-out-cancelled"
	EventOptOutEffective                 = RISC + "opt-out-effective"
	EventRecoveryActivated               = RISC + "recovery-activated"
	EventRecoveryInformationChanged      = RISC + "recovery-information-changed"
	EventSessionsRevoked                 = RISC + "sessions-revoked"
	EventVerification                    = SSF + "verification"
	EventStreamUpdated                   = SSF + "stream-updated"
)

// DefaultEventsRequested is the set a new stream asks for.
var DefaultEventsRequested = []string{
	EventSessionRevoked, EventCredentialChange, EventAssuranceLevelChange, EventTokenClaimsChange,
	EventAccountDisabled, EventAccountEnabled, EventAccountPurged, EventCredentialCompromise,
	EventSessionsRevoked, EventAccountCredentialChangeRequired,
}

// DefaultEndingEvents end local sessions that match the subject.
var DefaultEndingEvents = []string{
	EventSessionRevoked, EventAccountDisabled, EventAccountPurged, EventCredentialCompromise, EventSessionsRevoked,
}

func simpleSubject(identifier any, issuer string) map[string]string {
	doc, ok := AsMap(identifier)
	if !ok {
		return map[string]string{}
	}
	format := str(doc["format"])
	if format == "" {
		format = str(doc["subject_type"])
	}
	out := map[string]string{}
	switch format {
	case "iss_sub":
		if sub, ok := doc["sub"].(string); ok && (doc["iss"] == nil || str(doc["iss"]) == issuer) {
			out["sub"] = sub
		}
	case "email":
		if email, ok := doc["email"].(string); ok {
			out["email"] = email
		}
	case "opaque":
		if id, ok := doc["id"].(string); ok {
			out["opaque"] = id
		}
	case "aliases":
		items, _ := AsList(doc["identifiers"])
		for _, one := range items {
			for key, value := range simpleSubject(one, issuer) {
				out[key] = value
			}
		}
	}
	return out
}

// SubjectOf names the person, email, and provider session an event is about.
func SubjectOf(subID any, issuer string) map[string]string {
	doc, ok := AsMap(subID)
	if !ok {
		return map[string]string{}
	}
	format := str(doc["format"])
	if format == "" {
		format = str(doc["subject_type"])
	}
	out := map[string]string{}
	if format == "complex" || (format == "" && (doc["user"] != nil || doc["session"] != nil)) {
		user := simpleSubject(doc["user"], issuer)
		session := simpleSubject(doc["session"], issuer)
		if user["sub"] != "" {
			out["person"] = user["sub"]
		}
		if user["email"] != "" {
			out["email"] = user["email"]
		}
		sessionID := session["opaque"]
		if sessionID == "" {
			sessionID = session["sub"]
		}
		if sessionID != "" {
			out["idp_session"] = sessionID
		}
		return out
	}
	one := simpleSubject(doc, issuer)
	if one["sub"] != "" {
		out["person"] = one["sub"]
	}
	if one["email"] != "" {
		out["email"] = one["email"]
	}
	return out
}
