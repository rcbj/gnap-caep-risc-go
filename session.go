// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"strings"
	"time"
)

// TrackedSession is one local session that a signal can end.
type TrackedSession struct {
	LocalID    string
	Person     string
	Email      string
	IDPSession string
	ExpiresAt  *float64
}

// TrackedFromPerson copies the identifiers a grant subject can be found by.
func TrackedFromPerson(localID string, person *Person, expiresAt *float64) TrackedSession {
	session := TrackedSession{LocalID: localID, ExpiresAt: expiresAt}
	if person != nil {
		session.Person = person.Sub
		session.Email = person.Email
		session.IDPSession = person.Sid
	}
	return session
}

type memoryIndex struct {
	sessions map[string]TrackedSession
	order    []string
	max      int
}

func newMemoryIndex() *memoryIndex {
	return &memoryIndex{sessions: map[string]TrackedSession{}, max: 100000}
}

func (m *memoryIndex) add(session TrackedSession) {
	if _, exists := m.sessions[session.LocalID]; !exists && len(m.sessions) >= m.max {
		now := float64(time.Now().UnixMilli())
		for key, value := range m.sessions {
			if value.ExpiresAt != nil && *value.ExpiresAt <= now {
				m.remove(key)
			}
		}
		for len(m.sessions) >= m.max && len(m.order) > 0 {
			m.remove(m.order[0])
		}
	}
	if session.Email != "" {
		session.Email = strings.ToLower(session.Email)
	}
	if _, exists := m.sessions[session.LocalID]; !exists {
		m.order = append(m.order, session.LocalID)
	}
	m.sessions[session.LocalID] = session
}

func (m *memoryIndex) remove(localID string) {
	if _, ok := m.sessions[localID]; !ok {
		return
	}
	delete(m.sessions, localID)
	next := m.order[:0]
	for _, id := range m.order {
		if id != localID {
			next = append(next, id)
		}
	}
	m.order = next
}

func (m *memoryIndex) find(match func(TrackedSession) bool) []string {
	now := float64(time.Now().UnixMilli())
	var out []string
	for _, id := range append([]string{}, m.order...) {
		value, ok := m.sessions[id]
		if !ok {
			continue
		}
		if value.ExpiresAt != nil && *value.ExpiresAt <= now {
			m.remove(id)
			continue
		}
		if match(value) {
			out = append(out, id)
		}
	}
	return out
}

func (m *memoryIndex) byPerson(person string) []string {
	return m.find(func(session TrackedSession) bool { return session.Person == person })
}

func (m *memoryIndex) byEmail(email string) []string {
	wanted := strings.ToLower(email)
	return m.find(func(session TrackedSession) bool { return session.Email == wanted })
}

func (m *memoryIndex) byIDP(idp string) []string {
	return m.find(func(session TrackedSession) bool { return session.IDPSession == idp })
}
