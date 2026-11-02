// Package ca provides local sovereign Certificate Authority (CA) management
// for the Bonjoski security ecosystem. This file implements sovereign SPIFFE
// X.509-SVID generation, parsing, validation, and short-lived container TLS certificates.
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
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrEmptySPIFFEID              = errors.New("spiffe ID cannot be empty")
	ErrInvalidSPIFFEIDFormat      = errors.New("invalid spiffe ID format: must be spiffe://<trust-domain>/<path>")
	ErrInvalidSPIFFEScheme        = errors.New("invalid scheme: must be spiffe://")
	ErrSPIFFEQueryParamsForbidden = errors.New("spiffe ID must not contain query parameters or fragments")
	ErrTTLTooLong                 = errors.New("ephemeral SVID TTL cannot exceed 24 hours")
	ErrTTLTooShort                = errors.New("ephemeral SVID TTL must be at least 1 minute")
)

var spiffeIDRegex = regexp.MustCompile(`^spiffe://([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\./]+)$`)

// DefaultClockSkewPad is the default backdating buffer applied to NotBefore
// to accommodate clock drift in VMs and containers.
const DefaultClockSkewPad = 5 * time.Minute

// DefaultSVIDTTL is the default lifetime for an ephemeral SVID certificate.
const DefaultSVIDTTL = 1 * time.Hour

// MaxSVIDTTL is the maximum permitted lifetime for an ephemeral SVID.
const MaxSVIDTTL = 24 * time.Hour

// MinSVIDTTL is the minimum permitted lifetime for an ephemeral SVID.
const MinSVIDTTL = 1 * time.Minute

// SPIFFEID represents a parsed and validated SPIFFE identity URI.
type SPIFFEID struct {
	raw         string
	trustDomain string
	path        string
	url         *url.URL
}

// ParseSPIFFEID parses and strictly validates a SPIFFE ID string per the SPIFFE standard.
func ParseSPIFFEID(raw string) (*SPIFFEID, error) {
	if len(raw) == 0 {
		return nil, ErrEmptySPIFFEID
	}
	if strings.Contains(raw, "\x00") {
		return nil, ErrInvalidSPIFFEIDFormat
	}
	if strings.Contains(raw, "/../") || strings.HasSuffix(raw, "/..") || strings.HasPrefix(raw, "../") {
		return nil, fmt.Errorf("%w: path traversal detected", ErrInvalidSPIFFEIDFormat)
	}

	matches := spiffeIDRegex.FindStringSubmatch(raw)
	if len(matches) != 3 {
		return nil, ErrInvalidSPIFFEIDFormat
	}

	parsedURL, err := url.Parse(raw)
	if err != nil || parsedURL.Scheme != "spiffe" {
		return nil, ErrInvalidSPIFFEScheme
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, ErrSPIFFEQueryParamsForbidden
	}

	return &SPIFFEID{
		raw:         raw,
		trustDomain: matches[1],
		path:        matches[2],
		url:         parsedURL,
	}, nil
}

// String returns the full SPIFFE URI string.
func (s *SPIFFEID) String() string { return s.raw }

// TrustDomain returns the trust domain authority part of the SPIFFE URI.
func (s *SPIFFEID) TrustDomain() string { return s.trustDomain }

// Path returns the workload identity path within the trust domain.
func (s *SPIFFEID) Path() string { return s.path }

// URL returns the parsed net/url.URL representation.
func (s *SPIFFEID) URL() *url.URL { return s.url }

// SVIDProfile dictates certificate parameters for short-lived workloads.
type SVIDProfile struct {
	SPIFFEID     *SPIFFEID
	Hosts        []string
	TTL          time.Duration
	ClockSkewPad time.Duration
}

func validateSVIDProfile(profile *SVIDProfile) (time.Duration, time.Duration, error) {
	if profile == nil || profile.SPIFFEID == nil {
		return 0, 0, ErrInvalidSPIFFEIDFormat
	}
	ttl := profile.TTL
	if ttl <= 0 {
		ttl = DefaultSVIDTTL
	} else if ttl > MaxSVIDTTL {
		return 0, 0, ErrTTLTooLong
	} else if ttl < MinSVIDTTL {
		return 0, 0, ErrTTLTooShort
	}

	skewPad := profile.ClockSkewPad
	if skewPad <= 0 {
		skewPad = DefaultClockSkewPad
	}
	return ttl, skewPad, nil
}

func parseHosts(hosts []string) ([]string, []net.IP) {
	var dnsNames []string
	var ipAddresses []net.IP
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames, ipAddresses
}

func (c *CA) getOrg(cert *x509.Certificate) string {
	if cert != nil && len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return DefaultCAOrganization
}

// IssueSVID generates a short-lived classical ECDSA X.509-SVID signed by the Root CA.
func (c *CA) IssueSVID(profile *SVIDProfile) (certPEM, keyPEM []byte, err error) {
	if c.Certificate == nil || c.PrivateKey == nil {
		return nil, nil, errors.New("classical Root CA is not initialized")
	}

	ttl, skewPad, err := validateSVIDProfile(profile)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	dnsNames, ipAddresses := parseHosts(profile.Hosts)
	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   profile.SPIFFEID.String(),
			Organization: []string{c.getOrg(c.Certificate)},
		},
		URIs:                  []*url.URL{profile.SPIFFEID.URL()},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             now.Add(-skewPad),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.Certificate, &privKey.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign SVID certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ephemeral private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// IssuePQCSVID generates a short-lived post-quantum ML-DSA-65 X.509-SVID signed by the Post-Quantum Root CA.
func (c *CA) IssuePQCSVID(profile *SVIDProfile) (certPEM, keyPEM []byte, err error) {
	if c.PQCCertificate == nil || c.PQCPrivateKey == nil {
		return nil, nil, errors.New("post-quantum ML-DSA-65 CA is not initialized")
	}

	ttl, skewPad, err := validateSVIDProfile(profile)
	if err != nil {
		return nil, nil, err
	}

	srvKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral ML-DSA-65 key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	dnsNames, ipAddresses := parseHosts(profile.Hosts)
	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   profile.SPIFFEID.String(),
			Organization: []string{c.getOrg(c.PQCCertificate)},
		},
		URIs:                  []*url.URL{profile.SPIFFEID.URL()},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             now.Add(-skewPad),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.MLDSA65,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.PQCCertificate, srvKey.Public(), c.PQCPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign PQC SVID certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ephemeral PQC private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// IssueDualSVID signs both classical ECDSA and post-quantum ML-DSA-65 SVID certificates.
func (c *CA) IssueDualSVID(profile *SVIDProfile) (*IssuedCertBundle, error) {
	classicalCertPEM, classicalKeyPEM, err := c.IssueSVID(profile)
	if err != nil {
		return nil, err
	}

	bundle := &IssuedCertBundle{
		CertPEM:     classicalCertPEM,
		KeyPEM:      classicalKeyPEM,
		DualCertPEM: classicalCertPEM,
	}

	if c.PQCCertificate != nil && c.PQCPrivateKey != nil {
		pqcCertPEM, pqcKeyPEM, err := c.IssuePQCSVID(profile)
		if err == nil {
			bundle.PQCCertPEM = pqcCertPEM
			bundle.PQCKeyPEM = pqcKeyPEM
			bundle.DualCertPEM = append(append([]byte(nil), classicalCertPEM...), pqcCertPEM...)
		}
	}

	return bundle, nil
}
