// Package proxy implements the HTTP MITM proxy server.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "phoenix-ca.crt"
	caKeyFile  = "phoenix-ca.key"
)

// GenerateCA creates a self-signed CA certificate and private key, writing them
// to certPath and keyPath respectively. The CA is valid for 10 years.
func GenerateCA(certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Phoenix Security"},
			CommonName:   "Phoenix Security Supply Chain Firewall CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Write cert PEM
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encode cert PEM: %w", err)
	}

	// Write key PEM
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode key PEM: %w", err)
	}

	return nil
}

// LoadCA loads an existing CA certificate and key from the given file paths.
func LoadCA(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA keypair: %w", err)
	}
	return &cert, nil
}

// EnsureCA loads the CA from dir if it exists, or generates a new one.
// Returns the loaded TLS certificate.
func EnsureCA(dir string) (*tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	// Check if both files exist
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if certErr != nil || keyErr != nil {
		fmt.Printf("Generating new CA certificate in %s\n", dir)
		if err := GenerateCA(certPath, keyPath); err != nil {
			return nil, err
		}
	}

	return LoadCA(certPath, keyPath)
}

// DefaultCADir returns the default CA directory (~/.phoenix-firewall/ca/).
func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".phoenix-firewall", "ca")
	}
	return filepath.Join(home, ".phoenix-firewall", "ca")
}
