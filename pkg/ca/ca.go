// Package ca provides local sovereign Certificate Authority (CA) management
// for the Bonjoski security ecosystem. It enables zero-trust, hardware-bound
// root certificates, trusted local HTTPS servers, and mutual TLS (mTLS).
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultCAName         = "Bonjoski Sovereign Root CA"
	DefaultCAOrganization = "Bonjoski Sovereign AI Security Fabric"
	DefaultCAValidityDays = 3650 // 10 years
	DefaultCertValidity   = 365  // 1 year
)

// CA represents a loaded Certificate Authority capable of signing TLS certificates.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// GenerateRootCA creates a new self-signed Root Certificate Authority.
func GenerateRootCA(commonName, organization string, validityDays int) (*CA, error) {
	if commonName == "" {
		commonName = DefaultCAName
	}
	if organization == "" {
		organization = DefaultCAOrganization
	}
	if validityDays <= 0 {
		validityDays = DefaultCAValidityDays
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &CA{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// LoadCA parses an existing CA from PEM-encoded certificate and private key bytes.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid or missing CERTIFICATE PEM block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, errors.New("provided certificate is not a Certificate Authority")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid or missing private key PEM block")
	}

	var privKey *ecdsa.PrivateKey
	if keyBlock.Type == "EC PRIVATE KEY" {
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	} else if keyBlock.Type == "PRIVATE KEY" {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		var ok bool
		privKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not an ECDSA key")
		}
	} else {
		return nil, fmt.Errorf("unsupported private key block type: %s", keyBlock.Type)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// IssueServerCert signs a new TLS server certificate for the provided hostnames and IP addresses.
func (c *CA) IssueServerCert(hosts []string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	if validityDays <= 0 {
		validityDays = DefaultCertValidity
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	var dnsNames []string
	var ipAddresses []net.IP

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}

	cn := hosts[0]
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{c.Certificate.Subject.Organization[0]},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.Certificate, &serverPrivKey.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(serverPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal server private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// IssueClientCert signs a new TLS client certificate for mutual TLS (mTLS) authentication.
func (c *CA) IssueClientCert(clientIdentity string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if clientIdentity == "" {
		clientIdentity = "agent-client"
	}
	if validityDays <= 0 {
		validityDays = DefaultCertValidity
	}

	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate client private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   clientIdentity,
			Organization: []string{c.Certificate.Subject.Organization[0]},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.Certificate, &clientPrivKey.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(clientPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal client private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// TrustInSystemTrustStore installs the Root CA certificate into the macOS login keychain.
func TrustInSystemTrustStore(certPath string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("automatic trust store installation is only supported on macOS (current: %s)", runtime.GOOS)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	loginKeychain := filepath.Join(homeDir, "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(loginKeychain); os.IsNotExist(err) {
		// Fallback for older macOS
		loginKeychain = filepath.Join(homeDir, "Library", "Keychains", "login.keychain")
	}

	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", loginKeychain, certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-trusted-cert failed: %s (%w)", strings.TrimSpace(string(output)), err)
	}

	return nil
}

// UntrustFromSystemTrustStore removes the Root CA certificate from the macOS trust store.
func UntrustFromSystemTrustStore(certPath string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("automatic trust store removal is only supported on macOS (current: %s)", runtime.GOOS)
	}

	cmd := exec.Command("security", "remove-trusted-cert", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security remove-trusted-cert failed: %s (%w)", strings.TrimSpace(string(output)), err)
	}

	return nil
}
