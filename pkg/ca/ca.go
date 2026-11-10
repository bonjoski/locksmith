// Package ca provides local sovereign Certificate Authority (CA) management
// for the Bonjoski security ecosystem. It enables zero-trust, hardware-bound
// root certificates, trusted local HTTPS servers, and mutual TLS (mTLS).
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
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

	"github.com/bonjoski/locksmith/v2/pkg/ca/paranoid"
)

const (
	DefaultCAName         = "Bonjoski Sovereign Root CA"
	DefaultPQCCAName      = "Bonjoski Sovereign Post-Quantum Root CA (ML-DSA-65)"
	DefaultCAOrganization = "Bonjoski Sovereign AI Security Fabric"
	DefaultCAValidityDays = 3650 // 10 years
	DefaultCertValidity   = 365  // 1 year
)

// ErrForbiddenHostname is returned when a requested hostname or IP violates CA Name Constraints.
var ErrForbiddenHostname = errors.New("security violation: hostname or IP violates CA name constraints")

func validateIPPermitted(ip net.IP, permittedRanges []*net.IPNet) error {
	if len(permittedRanges) == 0 {
		return nil
	}
	for _, ipNet := range permittedRanges {
		if ipNet.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%w: IP %s is outside permitted CA IP ranges", ErrForbiddenHostname, ip)
}

func matchDomainConstraint(cleanHost, cleanPerm string) bool {
	if cleanPerm == "" {
		return false
	}
	if strings.HasPrefix(cleanPerm, ".") {
		return strings.HasSuffix(cleanHost, cleanPerm) || cleanHost == cleanPerm[1:]
	}
	return cleanHost == cleanPerm || strings.HasSuffix(cleanHost, "."+cleanPerm)
}

func validateDNSPermitted(cleanHost string, permittedDomains []string) error {
	if len(permittedDomains) == 0 {
		return nil
	}
	for _, perm := range permittedDomains {
		if matchDomainConstraint(cleanHost, strings.ToLower(perm)) {
			return nil
		}
	}
	return fmt.Errorf("%w: hostname %q is not within permitted CA domains %v", ErrForbiddenHostname, cleanHost, permittedDomains)
}

func validateHostPermitted(caCert *x509.Certificate, host string) error {
	if caCert == nil {
		return errors.New("CA certificate is nil: cannot validate name constraints")
	}
	if ip := net.ParseIP(host); ip != nil {
		return validateIPPermitted(ip, caCert.PermittedIPRanges)
	}
	return validateDNSPermitted(strings.ToLower(strings.TrimSpace(host)), caCert.PermittedDNSDomains)
}

func (c *CA) constraintCertificate() (*x509.Certificate, error) {
	if c == nil {
		return nil, errors.New("CA is nil")
	}
	if c.Certificate != nil {
		return c.Certificate, nil
	}
	if c.PQCCertificate != nil {
		return c.PQCCertificate, nil
	}
	return nil, errors.New("CA is not initialized: both classical and post-quantum certificates are nil")
}

// CA represents a dual-root Certificate Authority capable of signing both
// classical ECDSA and post-quantum ML-DSA-65 (NIST FIPS 204) certificates.
type CA struct {
	// Classical Root (ECDSA P-256) - trusted by macOS Keychain, curl, browsers
	Certificate    *x509.Certificate
	PrivateKey     *ecdsa.PrivateKey
	CertPEM        []byte
	KeyPEM         []byte

	// Post-Quantum Root (ML-DSA-65 / NIST FIPS 204)
	PQCCertificate *x509.Certificate
	PQCPrivateKey  *mldsa.PrivateKey
	PQCCertPEM     []byte
	PQCKeyPEM      []byte

	// Dual-Root concatenated bundle (Classical + PQC)
	DualCertPEM    []byte
}

// IssuedCertBundle represents a dual-issued certificate set.
type IssuedCertBundle struct {
	CertPEM     []byte // Classical ECDSA certificate
	KeyPEM      []byte // Classical ECDSA private key
	PQCCertPEM  []byte // Post-Quantum ML-DSA-65 certificate (FIPS 204)
	PQCKeyPEM   []byte // Post-Quantum ML-DSA-65 private key (PKCS#8 PEM)
	DualCertPEM []byte // Concatenated certificate bundle
}

// RootCAConfig defines configurable parameters and RFC 5280 Name Constraints for Root CA creation.
type RootCAConfig struct {
	CommonName          string
	Organization        string
	ValidityDays        int
	PermittedDNSDomains []string
	PermittedIPRanges   []*net.IPNet
	PermittedURIDomains []string
}

func resolveRootCANameConstraints(cfg *RootCAConfig) {
	if cfg.CommonName == "" {
		cfg.CommonName = DefaultCAName
	}
	if cfg.Organization == "" {
		cfg.Organization = DefaultCAOrganization
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = DefaultCAValidityDays
	}
	if len(cfg.PermittedDNSDomains) == 0 {
		cfg.PermittedDNSDomains = []string{"localhost", ".localhost"}
	}
	if len(cfg.PermittedIPRanges) == 0 {
		loopbackIPv4 := &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}
		loopbackIPv6 := &net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}
		cfg.PermittedIPRanges = []*net.IPNet{loopbackIPv4, loopbackIPv6}
	}
	if len(cfg.PermittedURIDomains) == 0 {
		cfg.PermittedURIDomains = []string{"bonjoski.local"}
	}
}

// GenerateRootCA creates a new self-signed dual-root Certificate Authority with default constraints.
func GenerateRootCA(commonName, organization string, validityDays int) (*CA, error) {
	return GenerateRootCAWithConfig(RootCAConfig{
		CommonName:   commonName,
		Organization: organization,
		ValidityDays: validityDays,
	})
}

// GenerateRootCAWithConfig creates a new self-signed dual-root Certificate Authority with explicit config.
func GenerateRootCAWithConfig(cfg RootCAConfig) (*CA, error) {
	resolveRootCANameConstraints(&cfg)

	// 0. Pre-Flight RNG Continuous Health Check (NIST SP 800-90B)
	if err := paranoid.CheckRNGHealth(rand.Reader); err != nil {
		return nil, fmt.Errorf("pre-flight CA RNG health check failed: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	// 1. Classical ECDSA P-256 Root CA
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}
	if err := paranoid.CheckECPrivateKey(privKey, paranoid.DefaultCheckOptions()); err != nil {
		return nil, fmt.Errorf("generated CA private key failed paranoid security verification: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,

		// RFC 5280 Name Constraints: restrict blast radius strictly to localhost, loopback, and local trust domains
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         cfg.PermittedDNSDomains,
		PermittedIPRanges:           cfg.PermittedIPRanges,
		PermittedURIDomains:         cfg.PermittedURIDomains,
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

	// 2. Post-Quantum ML-DSA-65 Root CA (NIST FIPS 204)
	pqcPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-65 CA private key: %w", err)
	}
	if err := paranoid.CheckMLDSA65PrivateKey(pqcPrivKey.Bytes()); err != nil {
		return nil, fmt.Errorf("generated PQC CA private key failed paranoid security verification: %w", err)
	}

	pqcSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC serial number: %w", err)
	}

	pqcCommonName := cfg.CommonName + " (Post-Quantum ML-DSA-65)"
	pqcTemplate := x509.Certificate{
		SerialNumber: pqcSerialNumber,
		Subject: pkix.Name{
			CommonName:   pqcCommonName,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.MLDSA65,

		// RFC 5280 Name Constraints: restrict blast radius strictly to localhost, loopback, and local trust domains
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         cfg.PermittedDNSDomains,
		PermittedIPRanges:           cfg.PermittedIPRanges,
		PermittedURIDomains:         cfg.PermittedURIDomains,
	}

	pqcCertDER, err := x509.CreateCertificate(rand.Reader, &pqcTemplate, &pqcTemplate, pqcPrivKey.Public(), pqcPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed PQC CA certificate: %w", err)
	}

	pqcCert, err := x509.ParseCertificate(pqcCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated PQC CA certificate: %w", err)
	}

	pqcCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pqcCertDER,
	})

	pqcKeyDER, err := x509.MarshalPKCS8PrivateKey(pqcPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PQC CA private key: %w", err)
	}
	pqcKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pqcKeyDER,
	})

	// 3. Concatenated Dual-Root Bundle (Classical + PQC)
	dualCertPEM := append(certPEM, pqcCertPEM...)

	return &CA{
		Certificate:    cert,
		PrivateKey:     privKey,
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		PQCCertificate: pqcCert,
		PQCPrivateKey:  pqcPrivKey,
		PQCCertPEM:     pqcCertPEM,
		PQCKeyPEM:      pqcKeyPEM,
		DualCertPEM:    dualCertPEM,
	}, nil
}

func parseAndVerifyCACert(certPEM []byte) (*x509.Certificate, error) {
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

	if err := paranoid.CheckCertificate(cert, paranoid.DefaultCheckOptions()); err != nil {
		return nil, fmt.Errorf("loaded CA certificate failed paranoid security verification: %w", err)
	}

	return cert, nil
}

func parseAndVerifyCAPrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, *mldsa.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid or missing private key PEM block")
	}

	var privKey *ecdsa.PrivateKey
	var pqcPrivKey *mldsa.PrivateKey

	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		var err error
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	case "PRIVATE KEY":
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		if ec, ok := pkcs8Key.(*ecdsa.PrivateKey); ok {
			privKey = ec
		} else if pqc, ok := pkcs8Key.(*mldsa.PrivateKey); ok {
			pqcPrivKey = pqc
		} else {
			return nil, nil, errors.New("private key is neither ECDSA nor ML-DSA")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported private key block type: %s", keyBlock.Type)
	}

	if pqcPrivKey != nil {
		if err := paranoid.CheckMLDSA65PrivateKey(pqcPrivKey.Bytes()); err != nil {
			return nil, nil, fmt.Errorf("loaded PQC CA private key failed paranoid security verification: %w", err)
		}
	} else if privKey != nil {
		if err := paranoid.CheckECPrivateKey(privKey, paranoid.DefaultCheckOptions()); err != nil {
			return nil, nil, fmt.Errorf("loaded CA private key failed paranoid security verification: %w", err)
		}
	}

	return privKey, pqcPrivKey, nil
}

// LoadCA parses an existing CA from PEM-encoded certificate and private key bytes.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseAndVerifyCACert(certPEM)
	if err != nil {
		return nil, err
	}

	privKey, pqcPrivKey, err := parseAndVerifyCAPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	if pqcPrivKey != nil {
		return &CA{
			PQCCertificate: cert,
			PQCPrivateKey:  pqcPrivKey,
			PQCCertPEM:     certPEM,
			PQCKeyPEM:      keyPEM,
			DualCertPEM:    certPEM,
		}, nil
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		DualCertPEM: certPEM,
	}, nil
}

// LoadDualCA parses both classical and post-quantum Root CAs into a unified Dual CA instance.
func LoadDualCA(certPEM, keyPEM, pqcCertPEM, pqcKeyPEM []byte) (*CA, error) {
	classicalCA, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load classical CA: %w", err)
	}

	if len(pqcCertPEM) > 0 && len(pqcKeyPEM) > 0 {
		pqcCA, err := LoadCA(pqcCertPEM, pqcKeyPEM)
		if err == nil && pqcCA.PQCCertificate != nil {
			classicalCA.PQCCertificate = pqcCA.PQCCertificate
			classicalCA.PQCPrivateKey = pqcCA.PQCPrivateKey
			classicalCA.PQCCertPEM = pqcCA.PQCCertPEM
			classicalCA.PQCKeyPEM = pqcCA.PQCKeyPEM
			classicalCA.DualCertPEM = append(classicalCA.CertPEM, pqcCA.PQCCertPEM...)
		}
	}

	return classicalCA, nil
}

func (c *CA) validateAndPartitionHosts(hosts []string) ([]string, []net.IP, error) {
	constraintCert, err := c.constraintCertificate()
	if err != nil {
		return nil, nil, err
	}
	var dnsNames []string
	var ipAddresses []net.IP
	for _, host := range hosts {
		if err := validateHostPermitted(constraintCert, host); err != nil {
			return nil, nil, err
		}
		if c.PQCCertificate != nil && c.PQCCertificate != constraintCert {
			if err := validateHostPermitted(c.PQCCertificate, host); err != nil {
				return nil, nil, err
			}
		}
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames, ipAddresses, nil
}

// IssueServerCert signs a new TLS server certificate for the provided hostnames and IP addresses.
func (c *CA) IssueServerCert(hosts []string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if c == nil || c.Certificate == nil || c.PrivateKey == nil {
		return nil, nil, errors.New("classical Root CA is not initialized")
	}
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
	if err := paranoid.CheckECPrivateKey(serverPrivKey, paranoid.DefaultCheckOptions()); err != nil {
		return nil, nil, fmt.Errorf("generated server private key failed paranoid verification: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	dnsNames, ipAddresses, err := c.validateAndPartitionHosts(hosts)
	if err != nil {
		return nil, nil, err
	}

	cn := hosts[0]
	org := DefaultCAOrganization
	if len(c.Certificate.Subject.Organization) > 0 {
		org = c.Certificate.Subject.Organization[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
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

// IssuePQCServerCert signs a post-quantum ML-DSA-65 server certificate.
func (c *CA) IssuePQCServerCert(hosts []string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if c.PQCCertificate == nil || c.PQCPrivateKey == nil {
		return nil, nil, errors.New("post-quantum ML-DSA-65 CA is not initialized")
	}
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	if validityDays <= 0 {
		validityDays = DefaultCertValidity
	}

	srvKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-DSA-65 server private key: %w", err)
	}
	if err := paranoid.CheckMLDSA65PrivateKey(srvKey.Bytes()); err != nil {
		return nil, nil, fmt.Errorf("generated PQC server private key failed paranoid verification: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	dnsNames, ipAddresses, err := c.validateAndPartitionHosts(hosts)
	if err != nil {
		return nil, nil, err
	}

	cn := hosts[0]
	org := DefaultCAOrganization
	if len(c.PQCCertificate.Subject.Organization) > 0 {
		org = c.PQCCertificate.Subject.Organization[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		SignatureAlgorithm:    x509.MLDSA65,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.PQCCertificate, srvKey.Public(), c.PQCPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign PQC server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal PQC server private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// IssueDualServerCert signs both classical ECDSA and post-quantum ML-DSA-65 server certificates.
func (c *CA) IssueDualServerCert(hosts []string, validityDays int) (*IssuedCertBundle, error) {
	classicalCertPEM, classicalKeyPEM, err := c.IssueServerCert(hosts, validityDays)
	if err != nil {
		return nil, err
	}

	bundle := &IssuedCertBundle{
		CertPEM:     classicalCertPEM,
		KeyPEM:      classicalKeyPEM,
		DualCertPEM: classicalCertPEM,
	}

	if c.PQCCertificate != nil && c.PQCPrivateKey != nil {
		pqcCertPEM, pqcKeyPEM, err := c.IssuePQCServerCert(hosts, validityDays)
		if err != nil {
			return nil, fmt.Errorf("failed to issue PQC server certificate: %w", err)
		}
		bundle.PQCCertPEM = pqcCertPEM
		bundle.PQCKeyPEM = pqcKeyPEM
		bundle.DualCertPEM = append(classicalCertPEM, pqcCertPEM...)
	}

	return bundle, nil
}

// IssueClientCert signs a new TLS client certificate for mutual TLS (mTLS) authentication.
func (c *CA) IssueClientCert(clientIdentity string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if c == nil || c.Certificate == nil || c.PrivateKey == nil {
		return nil, nil, errors.New("classical Root CA is not initialized")
	}
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
	if err := paranoid.CheckECPrivateKey(clientPrivKey, paranoid.DefaultCheckOptions()); err != nil {
		return nil, nil, fmt.Errorf("generated client private key failed paranoid verification: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	org := DefaultCAOrganization
	if len(c.Certificate.Subject.Organization) > 0 {
		org = c.Certificate.Subject.Organization[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   clientIdentity,
			Organization: []string{org},
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

// IssuePQCClientCert signs a post-quantum ML-DSA-65 client certificate.
func (c *CA) IssuePQCClientCert(clientIdentity string, validityDays int) (certPEM, keyPEM []byte, err error) {
	if c.PQCCertificate == nil || c.PQCPrivateKey == nil {
		return nil, nil, errors.New("post-quantum ML-DSA-65 CA is not initialized")
	}
	if clientIdentity == "" {
		clientIdentity = "agent-client"
	}
	if validityDays <= 0 {
		validityDays = DefaultCertValidity
	}

	clientKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-DSA-65 client private key: %w", err)
	}
	if err := paranoid.CheckMLDSA65PrivateKey(clientKey.Bytes()); err != nil {
		return nil, nil, fmt.Errorf("generated PQC client private key failed paranoid verification: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	org := DefaultCAOrganization
	if len(c.PQCCertificate.Subject.Organization) > 0 {
		org = c.PQCCertificate.Subject.Organization[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   clientIdentity,
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.MLDSA65,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.PQCCertificate, clientKey.Public(), c.PQCPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign PQC client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal PQC client private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// IssueDualClientCert signs both classical ECDSA and post-quantum ML-DSA-65 client certificates.
func (c *CA) IssueDualClientCert(clientIdentity string, validityDays int) (*IssuedCertBundle, error) {
	classicalCertPEM, classicalKeyPEM, err := c.IssueClientCert(clientIdentity, validityDays)
	if err != nil {
		return nil, err
	}

	bundle := &IssuedCertBundle{
		CertPEM:     classicalCertPEM,
		KeyPEM:      classicalKeyPEM,
		DualCertPEM: classicalCertPEM,
	}

	if c.PQCCertificate != nil && c.PQCPrivateKey != nil {
		pqcCertPEM, pqcKeyPEM, err := c.IssuePQCClientCert(clientIdentity, validityDays)
		if err != nil {
			return nil, fmt.Errorf("failed to issue PQC client certificate: %w", err)
		}
		bundle.PQCCertPEM = pqcCertPEM
		bundle.PQCKeyPEM = pqcKeyPEM
		bundle.DualCertPEM = append(classicalCertPEM, pqcCertPEM...)
	}

	return bundle, nil
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
