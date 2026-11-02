// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package gnap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// KeyPair is a self-signed P-256 key and certificate kept in this process.
type KeyPair struct {
	PrivateKeyPEM  string
	CertificatePEM string
	Fingerprint    string
	Certificate    *x509.Certificate
	Private        *ecdsa.PrivateKey
}

// CreateSelfSignedKeyPair builds a P-256 certificate whose only key usage is digitalSignature.
func CreateSelfSignedKeyPair(commonName string, dns []string, ips []string) (*KeyPair, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-60 * time.Second),
		NotAfter:              time.Now().Add(1095 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              dns,
	}
	for _, address := range ips {
		if ip := net.ParseIP(address); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Fingerprint:    Fingerprint256(cert),
		Certificate:    cert,
		Private:        private,
	}, nil
}
