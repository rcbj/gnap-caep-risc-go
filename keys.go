// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var proofs = []string{"mtls", "httpsig", "jwsd"}

var certRE = regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`)
var b64URLRE = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// ClientKey is the one key this process proves. The private half is not sent.
type ClientKey struct {
	Proof    string
	Private  any
	Thumb    string
	Alg      string
	Kid      string
	JWK      map[string]string
	CertPEM  string
	ChainPEM string
}

func (k *ClientKey) PrivatePEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func jwkThumbprint(jwk map[string]string) (string, error) {
	var raw string
	switch jwk["kty"] {
	case "EC":
		raw = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk["crv"], jwk["x"], jwk["y"])
	case "RSA":
		raw = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk["e"], jwk["n"])
	case "OKP":
		raw = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, jwk["crv"], jwk["x"])
	default:
		return "", fmtFail("config", "a %s key is not a GNAP client key this library loads", jwk["kty"])
	}
	sum := sha256.Sum256([]byte(raw))
	return B64URL(sum[:]), nil
}

func algOf(jwk map[string]string) (string, error) {
	if alg := jwk["alg"]; alg != "" && alg != "none" {
		return alg, nil
	}
	switch jwk["kty"] {
	case "EC":
		switch jwk["crv"] {
		case "P-256":
			return "ES256", nil
		case "P-384":
			return "ES384", nil
		case "P-521":
			return "ES512", nil
		default:
			shown := jwk["crv"]
			if shown == "" {
				shown = "(none)"
			}
			return "", fmtFail("config", "the curve %s has no signature algorithm", shown)
		}
	case "RSA":
		return "RS256", nil
	case "OKP":
		return "EdDSA", nil
	default:
		return "", fmtFail("config", "a %s key is not a GNAP client key this library loads", jwk["kty"])
	}
}

func curveName(curve elliptic.Curve) (string, error) {
	switch curve.Params().BitSize {
	case 256:
		return "P-256", nil
	case 384:
		return "P-384", nil
	case 521:
		return "P-521", nil
	default:
		return "", fail("config", "a key of this type is not a GNAP client key this library loads")
	}
}

func unsigned(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}
	return n.Bytes()
}

func publicJWK(private any) (map[string]string, error) {
	jwk := map[string]string{}
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		name, err := curveName(key.Curve)
		if err != nil {
			return nil, err
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		x := make([]byte, size)
		y := make([]byte, size)
		key.X.FillBytes(x)
		key.Y.FillBytes(y)
		jwk["kty"] = "EC"
		jwk["crv"] = name
		jwk["x"] = B64URL(x)
		jwk["y"] = B64URL(y)
	case *rsa.PrivateKey:
		jwk["kty"] = "RSA"
		jwk["n"] = B64URL(unsigned(key.N))
		jwk["e"] = B64URL(unsigned(big.NewInt(int64(key.E))))
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		jwk["kty"] = "OKP"
		jwk["crv"] = "Ed25519"
		jwk["x"] = B64URL(pub)
	default:
		return nil, fail("config", "a key of this type is not a GNAP client key this library loads")
	}
	alg, err := algOf(jwk)
	if err != nil {
		return nil, err
	}
	jwk["alg"] = alg
	thumb, err := jwkThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk["kid"] = thumb
	return jwk, nil
}

func b64urlStrict(value, what string) ([]byte, error) {
	if !b64URLRE.MatchString(value) {
		return nil, fail("signature", "the JWS "+what+" is not base64url")
	}
	raw, err := B64URLDecode(value)
	if err != nil {
		return nil, fail("signature", "the JWS "+what+" is not base64url")
	}
	return raw, nil
}

func PublicKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	kty := str(jwk["kty"])
	kid := str(jwk["kid"])
	switch kty {
	case "RSA":
		nb, err := b64urlStrict(str(jwk["n"]), "signature")
		if err != nil {
			return nil, failCause("signature", "the key "+kid+" cannot be read: "+err.Error(), err)
		}
		eb, err := b64urlStrict(str(jwk["e"]), "signature")
		if err != nil {
			return nil, failCause("signature", "the key "+kid+" cannot be read: "+err.Error(), err)
		}
		n := new(big.Int).SetBytes(nb)
		e := int(new(big.Int).SetBytes(eb).Int64())
		if e < 2 || n.Sign() <= 0 {
			return nil, fail("signature", "the key "+kid+" cannot be read: bad RSA numbers")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch str(jwk["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fail("signature", "the key "+kid+" cannot be read: unsupported curve")
		}
		xb, err := b64urlStrict(str(jwk["x"]), "signature")
		if err != nil {
			return nil, failCause("signature", "the key "+kid+" cannot be read: "+err.Error(), err)
		}
		yb, err := b64urlStrict(str(jwk["y"]), "signature")
		if err != nil {
			return nil, failCause("signature", "the key "+kid+" cannot be read: "+err.Error(), err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	case "OKP":
		raw, err := b64urlStrict(str(jwk["x"]), "signature")
		if err != nil {
			return nil, failCause("signature", "the key "+kid+" cannot be read: "+err.Error(), err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fail("signature", "the key "+kid+" cannot be read: bad Ed25519 key")
		}
		return ed25519.PublicKey(raw), nil
	default:
		return nil, fmtFail("signature", "the key %s cannot be read: unsupported %s", kid, kty)
	}
}

func PublicKeyObject(key *ClientKey) (map[string]any, error) {
	if key.Proof == "mtls" {
		if strings.TrimSpace(key.CertPEM) == "" {
			return nil, fail("config", "mutual TLS needs the client certificate")
		}
		return map[string]any{"proof": "mtls", "cert": strings.TrimSpace(key.CertPEM)}, nil
	}
	if key.JWK == nil {
		return nil, fail("config", key.Proof+" needs a JWK")
	}
	jwk := map[string]any{"kty": key.JWK["kty"]}
	for _, name := range []string{"crv", "x", "y", "n", "e"} {
		if key.JWK[name] != "" {
			jwk[name] = key.JWK[name]
		}
	}
	jwk["alg"] = key.Alg
	jwk["kid"] = key.Kid
	return map[string]any{"proof": key.Proof, "jwk": jwk}, nil
}

func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		return crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		return crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		return crypto.SHA512, nil
	default:
		return 0, fmtFail("config", "this library does not sign with %s", alg)
	}
}

func digest(alg string, data []byte) ([]byte, crypto.Hash, error) {
	h, err := hashFor(alg)
	if err != nil {
		return nil, 0, err
	}
	sum := h.New()
	_, _ = sum.Write(data)
	return sum.Sum(nil), h, nil
}

func SignRaw(key *ClientKey, data []byte) ([]byte, error) {
	alg := key.Alg
	switch private := key.Private.(type) {
	case ed25519.PrivateKey:
		if alg != "EdDSA" && alg != "Ed25519" {
			return nil, fmtFail("config", "this library does not sign with %s", alg)
		}
		return ed25519.Sign(private, data), nil
	case *ecdsa.PrivateKey:
		sum, _, err := digest(alg, data)
		if err != nil {
			return nil, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, private, sum)
		if err != nil {
			return nil, failCause("signature", err.Error(), err)
		}
		size := (private.Curve.Params().BitSize + 7) / 8
		out := make([]byte, size*2)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	case *rsa.PrivateKey:
		sum, h, err := digest(alg, data)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(alg, "PS") {
			return rsa.SignPSS(rand.Reader, private, h, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		}
		return rsa.SignPKCS1v15(rand.Reader, private, h, sum)
	default:
		return nil, fail("config", "a key of this type is not a GNAP client key this library loads")
	}
}

func VerifyRaw(public crypto.PublicKey, alg string, data, signature []byte) bool {
	switch pub := public.(type) {
	case ed25519.PublicKey:
		if alg != "EdDSA" && alg != "Ed25519" {
			return false
		}
		return ed25519.Verify(pub, data, signature)
	case *ecdsa.PublicKey:
		sum, _, err := digest(alg, data)
		if err != nil || len(signature) == 0 || len(signature)%2 != 0 {
			return false
		}
		size := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return ecdsa.Verify(pub, sum, r, s)
	case *rsa.PublicKey:
		sum, h, err := digest(alg, data)
		if err != nil {
			return false
		}
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pub, h, sum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, h, sum, signature) == nil
	default:
		return false
	}
}

func certBlocks(text string) []string {
	return certRE.FindAllString(text, -1)
}

func Fingerprint256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func samePublic(a, b crypto.PublicKey) bool {
	left, err1 := x509.MarshalPKIXPublicKey(a)
	right, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmacEqual(left, right)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func publicOf(private any) (crypto.PublicKey, error) {
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey), nil
	default:
		return nil, fail("config", "a key of this type is not a GNAP client key this library loads")
	}
}

func parsePrivate(text string) (any, error) {
	rest := []byte(text)
	var last error
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			continue
		}
		if err == nil && key != nil {
			return key, nil
		}
		last = err
	}
	if last != nil {
		return nil, failCause("config", "the private key could not be read: "+last.Error(), last)
	}
	return nil, fail("config", "the private key could not be read: no PEM key")
}

func parseCert(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fail("config", "the certificate could not be read: no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, failCause("config", "the certificate could not be read: "+err.Error(), err)
	}
	return cert, nil
}

func LoadClientKey(privatePEM, certificatePEM, proof string) (*ClientKey, error) {
	private, err := parsePrivate(privatePEM)
	if err != nil {
		return nil, err
	}
	jwk, err := publicJWK(private)
	if err != nil {
		return nil, err
	}
	var cert *x509.Certificate
	if strings.TrimSpace(certificatePEM) != "" {
		cert, err = parseCert(certificatePEM)
		if err != nil {
			return nil, err
		}
		pub, err := publicOf(private)
		if err != nil {
			return nil, err
		}
		if !samePublic(pub, cert.PublicKey) {
			return nil, fail("config", "the certificate is not the public half of the private key")
		}
	}
	chosen := proof
	if chosen == "" {
		if cert != nil {
			chosen = "mtls"
		} else {
			chosen = "httpsig"
		}
	}
	if chosen == "mtls" && cert == nil {
		return nil, fail("config", `keyProof "mtls" needs certificate`)
	}
	if chosen == "mtls" {
		blocks := certBlocks(certificatePEM)
		leafSource := certificatePEM
		if len(blocks) > 0 {
			leafSource = blocks[0]
		}
		leaf := strings.TrimSpace(leafSource) + "\n"
		chainSource := blocks
		if len(chainSource) == 0 {
			chainSource = []string{certificatePEM}
		}
		parts := make([]string, len(chainSource))
		for i, block := range chainSource {
			parts[i] = strings.TrimSpace(block)
		}
		sum := sha256.Sum256(cert.Raw)
		return &ClientKey{
			Proof: "mtls", Private: private, Thumb: B64URL(sum[:]), Alg: jwk["alg"], Kid: jwk["kid"],
			JWK: jwk, CertPEM: leaf, ChainPEM: strings.Join(parts, "\n") + "\n",
		}, nil
	}
	stored := ""
	if certificatePEM != "" {
		stored = certificatePEM
	}
	return &ClientKey{
		Proof: chosen, Private: private, Thumb: jwk["kid"], Alg: jwk["alg"], Kid: jwk["kid"],
		JWK: jwk, CertPEM: stored,
	}, nil
}

// Keep sha512 referenced for the digest switch on SHA-384/512 via crypto.Hash.
var _ = sha512.New
