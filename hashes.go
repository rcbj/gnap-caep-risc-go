// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

// InteractionHash is base64url(SHA-256(clientNonce, serverNonce, interact_ref, grant endpoint)) separated by newlines.
func InteractionHash(clientNonce, serverNonce, interactRef, grantEndpoint string) string {
	raw := clientNonce + "\n" + serverNonce + "\n" + interactRef + "\n" + grantEndpoint
	return B64URL(SHA256([]byte(raw)))
}

func HashEqual(a, b string) bool {
	return TimingEqual(a, b)
}
