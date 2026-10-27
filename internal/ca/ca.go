package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	CertFile = "selfsigned.crt"
	KeyFile  = "selfsigned.key"
)

// Ensure creates (or reuses) a self-signed certificate that is also its own
// trust anchor. This mirrors what ageLANServer does for AoE2: a single
// self-signed certificate installed in the Windows "Trusted Root" store.
//
// Using a self-signed leaf instead of a CA + leaf chain matters on Windows:
// Schannel performs revocation checking on non-root certificates, and it fails
// with CRYPT_E_NO_REVOCATION_CHECK (0x80092012) when the certificate has no
// CRL/OCSP endpoint. A trusted self-signed root is its own anchor, so no
// revocation check is attempted.
func Ensure(dir string, domains []string, force bool) (certPath string, keyPath string, err error) {
	if err = os.MkdirAll(dir, 0755); err != nil {
		return
	}
	certPath = filepath.Join(dir, CertFile)
	keyPath = filepath.Join(dir, KeyFile)

	if !force {
		if _, statErr := os.Stat(certPath); statErr == nil {
			if _, statErr = os.Stat(keyPath); statErr == nil {
				var pair tls.Certificate
				if pair, err = tls.LoadX509KeyPair(certPath, keyPath); err == nil {
					if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
						if time.Now().Add(24*time.Hour).Before(leaf.NotAfter) && coversAll(leaf, domains) {
							return certPath, keyPath, nil
						}
					}
				}
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	dnsNames := buildDNSNames(domains)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "HostSpy Self-signed",
			Organization: []string{"HostSpy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		DNSNames:              dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err = os.WriteFile(certPath, certPEM, 0644); err != nil {
		return
	}
	if err = os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return
	}

	fmt.Printf("[HOSTSPY][CERT] Generated self-signed certificate for %d names\n", len(dnsNames))
	return certPath, keyPath, nil
}

func buildDNSNames(domains []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(domains)+3)
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	for _, d := range domains {
		add(d)
	}
	// Wildcards used by the AoE2 client (and safe for anything else we add).
	add("*." + "worldsedgelink.com")
	add("*." + "ageofempires.com")
	add("*.playfabapi.com")
	return out
}

// coversAll reports whether the existing certificate already has every name.
func coversAll(cert *x509.Certificate, domains []string) bool {
	have := map[string]bool{}
	for _, d := range cert.DNSNames {
		have[d] = true
	}
	for _, want := range buildDNSNames(domains) {
		if !have[want] {
			return false
		}
	}
	return true
}

// Load returns a ready-to-serve certificate.
func Load(certPath, keyPath string) (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("empty certificate")
	}
	pair.Leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	return &pair, nil
}
