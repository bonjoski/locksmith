package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
	"github.com/spf13/cobra"
	"golang.org/x/time/rate"
)

var (
	caCommonName       string
	caOrg              string
	caDays             int
	caAutoTrust        bool
	caServerHosts      []string
	caClientName       string
	caIsClient         bool
	caOutCert          string
	caOutKey           string
	caUntrust          bool
	caSpiffeID         string
	caTTL              time.Duration
	caExportOutDir     string
	caExportFormat     string
	caExportName       string
	caExportRenew          bool
	caServeSocket          string
	caServeTrustDomain     string
	caServePolicyPath      string
	caServeRateLimit       float64
	caServeVsockPort       uint32
	caAllowUnsealedDiskKeys bool
	caForceUnconstrained   bool
	caServeBridgeToken        string
	caServeBridgeTokenFile    string
	caServeBridgeKeyFile      string
	caServeAllowedCIDs        []uint
	caPermittedDNS            []string
	caPermittedIP             []string
	caPermittedURI            []string
	caAllowBroadDomains       bool
	caCustomCADir             string
	caServeNoPersistBridgeKey bool
	caDeriveCID               uint32
	caDeriveKeyFile           string
)

const (
	secretRootCAKey   = "ca:root:key"
	secretRootCACert  = "ca:root:cert"
	secretRootPQCKey  = "ca:root:pqc:key"
	secretRootPQCCert = "ca:root:pqc:cert"
)

func writeKeyFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			_ = rmErr
		}
	}()

	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsMulticast() {
		return false
	}
	if ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsLinkLocalUnicast() {
		return true
	}
	cgnat := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	return cgnat.Contains(ip4)
}

func isPrivateIPv6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	if ip.IsMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func isPrivateOrLoopbackIPv4Net(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 8 {
		return false
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return false
	}
	mask4 := net.CIDRMask(ones, 32)
	baseIP := ip4.Mask(mask4)
	lastIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		lastIP[i] = baseIP[i] | ^mask4[i]
	}
	if baseIP.IsMulticast() || lastIP.IsMulticast() {
		return false
	}
	return isPrivateIPv4(baseIP) && isPrivateIPv4(lastIP)
}

func isPrivateOrLoopbackIPv6Net(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	if bits != 128 || ones < 7 {
		return false
	}
	ip16 := ipNet.IP.To16()
	if ip16 == nil {
		return false
	}
	mask16 := net.CIDRMask(ones, 128)
	baseIP := ip16.Mask(mask16)
	lastIP := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		lastIP[i] = baseIP[i] | ^mask16[i]
	}
	if baseIP.IsMulticast() || lastIP.IsMulticast() {
		return false
	}
	return isPrivateIPv6(baseIP) && isPrivateIPv6(lastIP)
}

func isPrivateOrLoopbackIPNet(ipNet *net.IPNet) bool {
	if ipNet == nil || ipNet.IP == nil {
		return false
	}
	if ipNet.IP.To4() != nil {
		return isPrivateOrLoopbackIPv4Net(ipNet)
	}
	return isPrivateOrLoopbackIPv6Net(ipNet)
}

func isBroadDomain(domain string) bool {
	clean := strings.ToLower(strings.TrimSpace(domain))
	clean = strings.TrimPrefix(clean, ".")
	clean = strings.TrimSuffix(clean, ".")
	return clean == "local" || strings.HasSuffix(clean, ".local") ||
		clean == "internal" || strings.HasSuffix(clean, ".internal") ||
		clean == "home.arpa" || strings.HasSuffix(clean, ".home.arpa")
}

func hasPublicTLD(domain string) bool {
	clean := strings.ToLower(strings.TrimSpace(domain))
	clean = strings.TrimPrefix(clean, ".")
	clean = strings.TrimSuffix(clean, ".")
	publicSuffixes := []string{
		"com", "net", "org", "edu", "gov", "mil", "io", "dev", "app",
		"ai", "co", "info", "biz", "xyz", "me", "cloud", "online", "site",
		"tech", "us", "uk", "ca", "de", "fr", "jp", "cn", "au", "ru", "br", "in",
	}
	for _, suffix := range publicSuffixes {
		if clean == suffix || strings.HasSuffix(clean, "."+suffix) {
			return true
		}
	}
	return false
}

func isSovereignDomain(domain string) error {
	clean := strings.ToLower(strings.TrimSpace(domain))
	clean = strings.TrimSuffix(clean, ".")
	if clean == "" || clean == "*" || clean == "." {
		return fmt.Errorf("invalid empty or wildcard domain constraint %q", domain)
	}

	cleanNoDot := strings.TrimPrefix(clean, ".")
	if !strings.Contains(cleanNoDot, ".") && cleanNoDot != "localhost" && cleanNoDot != "local" && cleanNoDot != "internal" && cleanNoDot != "home.arpa" {
		return fmt.Errorf("domain %q is an invalid dotless TLD constraint; must be localhost or have a sovereign domain suffix", domain)
	}

	if cleanNoDot == "lan" || strings.HasSuffix(cleanNoDot, ".lan") {
		return fmt.Errorf("domain %q uses .lan which is not an IETF sovereign reserved domain; use .local, .internal, or .home.arpa", domain)
	}

	if hasPublicTLD(clean) {
		return fmt.Errorf("domain %q contains public internet domain", domain)
	}
	return nil
}

func validateRootCriticalAndPathLen(cert *x509.Certificate) error {
	if !cert.PermittedDNSDomainsCritical {
		return errors.New("Name Constraints extension is not marked critical (RFC 5280)")
	}
	if !cert.MaxPathLenZero {
		return errors.New("BasicConstraints MaxPathLenZero must be true to prevent subordinate CA issuance")
	}
	return nil
}

func validateRootIPRanges(cert *x509.Certificate) error {
	if len(cert.PermittedIPRanges) == 0 {
		return errors.New("missing PermittedIPRanges (must restrict to loopback/private CIDRs)")
	}
	for _, ipNet := range cert.PermittedIPRanges {
		if !isPrivateOrLoopbackIPNet(ipNet) {
			return fmt.Errorf("PermittedIPRanges includes non-private IP range %s", ipNet)
		}
	}
	return nil
}

func validateRootDNSDomains(cert *x509.Certificate) error {
	if len(cert.PermittedDNSDomains) == 0 {
		return errors.New("missing PermittedDNSDomains")
	}
	for _, d := range cert.PermittedDNSDomains {
		if err := isSovereignDomain(d); err != nil {
			return fmt.Errorf("invalid PermittedDNSDomains entry %q: %w", d, err)
		}
	}
	return nil
}

func validateRootURIDomains(cert *x509.Certificate) error {
	if len(cert.PermittedURIDomains) == 0 {
		return nil
	}
	for _, uriDomain := range cert.PermittedURIDomains {
		clean := strings.TrimSpace(uriDomain)
		if idx := strings.Index(clean, "://"); idx != -1 {
			clean = clean[idx+3:]
		}
		if slashIdx := strings.Index(clean, "/"); slashIdx != -1 {
			clean = clean[:slashIdx]
		}
		if err := isSovereignDomain(clean); err != nil {
			return fmt.Errorf("invalid PermittedURIDomains entry %q: %w", uriDomain, err)
		}
	}
	return nil
}

func validateRootSecurityProfile(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("missing root certificate")
	}
	if err := validateRootCriticalAndPathLen(cert); err != nil {
		return err
	}
	if err := validateRootIPRanges(cert); err != nil {
		return err
	}
	if err := validateRootDNSDomains(cert); err != nil {
		return err
	}
	return validateRootURIDomains(cert)
}

func parsePermittedIPs(raw []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, ipStr := range raw {
		trimmed := strings.TrimSpace(ipStr)
		if trimmed == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(trimmed); err == nil {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				ones, _ := ipNet.Mask.Size()
				nets = append(nets, &net.IPNet{
					IP:   ip4,
					Mask: net.CIDRMask(ones, 32),
				})
			} else {
				nets = append(nets, ipNet)
			}
		} else if ip := net.ParseIP(trimmed); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		} else {
			return nil, fmt.Errorf("invalid permitted-ip %q: must be valid CIDR or IP address", trimmed)
		}
	}
	return nets, nil
}

func getDefaultCADir() string {
	if caCustomCADir != "" {
		return caCustomCADir
	}
	if env := os.Getenv("LOCKSMITH_CA_DIR"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".locksmith/ca"
	}
	return filepath.Join(home, ".locksmith", "ca")
}

func getDefaultCertsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".locksmith/certs"
	}
	return filepath.Join(home, ".locksmith", "certs")
}

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Hardware-bound sovereign Certificate Authority (CA) and local TLS management",
	Long: `Manage the local hardware-bound Certificate Authority (CA) for the Bonjoski security ecosystem.
Allows creating a sovereign local Root CA anchored in your hardware enclave, issuing trusted
HTTPS server certificates for local loopback daemons (Shield, Aegisbox), and mutual TLS (mTLS) client certificates.`,
}

func validateInitConfig() ([]*net.IPNet, error) {
	for _, d := range caPermittedDNS {
		if isBroadDomain(d) && !caAllowBroadDomains {
			return nil, fmt.Errorf("domain %q requires --allow-broad-domains flag", d)
		}
		if err := isSovereignDomain(d); err != nil {
			return nil, fmt.Errorf("invalid --permitted-dns domain %q: %w", d, err)
		}
	}
	for _, u := range caPermittedURI {
		clean := strings.TrimSpace(u)
		if idx := strings.Index(clean, "://"); idx != -1 {
			clean = clean[idx+3:]
		}
		if slashIdx := strings.Index(clean, "/"); slashIdx != -1 {
			clean = clean[:slashIdx]
		}
		if err := isSovereignDomain(clean); err != nil {
			return nil, fmt.Errorf("invalid --permitted-uri domain %q: %w", u, err)
		}
	}
	return parsePermittedIPs(caPermittedIP)
}

var caInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the sovereign Dual-Root Certificate Authority (ECDSA + ML-DSA-65)",
	Long: `Generate a new self-signed Dual-Root Certificate Authority (CA) combining classical ECDSA
and Post-Quantum ML-DSA-65 (NIST FIPS 204).
The Root CA private keys are securely sealed inside your platform enclave (macOS Keychain with Touch ID).
The public classical certificate is exported to ~/.locksmith/ca/root-ca.crt (trusted by macOS Keychain).
The public post-quantum certificate is exported to ~/.locksmith/ca/root-ca-pqc.crt.
A unified dual bundle is exported to ~/.locksmith/ca/root-ca-dual.crt.
Use --trust to automatically install the classical Root CA into the macOS system trust store.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		caDir := getDefaultCADir()
		if err := os.MkdirAll(caDir, 0700); err != nil {
			return fmt.Errorf("failed to create CA directory %s: %w", caDir, err)
		}

		rootCertPath := filepath.Join(caDir, "root-ca.crt")
		rootKeyPath := filepath.Join(caDir, "root-ca.key")
		pqcCertPath := filepath.Join(caDir, "root-ca-pqc.crt")
		pqcKeyPath := filepath.Join(caDir, "root-ca-pqc.key")
		dualCertPath := filepath.Join(caDir, "root-ca-dual.crt")

		permittedIPNets, err := validateInitConfig()
		if err != nil {
			return err
		}

		newCA, err := ca.GenerateRootCAWithConfig(ca.RootCAConfig{
			CommonName:          caCommonName,
			Organization:        caOrg,
			ValidityDays:        caDays,
			PermittedDNSDomains: caPermittedDNS,
			PermittedIPRanges:   permittedIPNets,
			PermittedURIDomains: caPermittedURI,
		})
		if err != nil {
			return fmt.Errorf("failed to generate Dual Root CA: %w", err)
		}

		// 1. Write public certificates with standard read permissions
		if err := writeKeyFileAtomic(rootCertPath, newCA.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootCertPath, err)
		}
		if len(newCA.PQCCertPEM) > 0 {
			if err := writeKeyFileAtomic(pqcCertPath, newCA.PQCCertPEM, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", pqcCertPath, err)
			}
		}
		if len(newCA.DualCertPEM) > 0 {
			if err := writeKeyFileAtomic(dualCertPath, newCA.DualCertPEM, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", dualCertPath, err)
			}
		}

		// 2. Hardware Enclave Sealing (macOS Keychain / TPM)
		enclaveSealed := false
		if ls != nil {
			expiresAt := time.Now().Add(time.Duration(caDays) * 24 * time.Hour)
			keyCopy := append([]byte(nil), newCA.KeyPEM...)
			certCopy := append([]byte(nil), newCA.CertPEM...)
			err1 := ls.SetWithContext(secretRootCAKey, keyCopy, expiresAt, globalBiometricReqs, "token", "locksmith-ca", "", nil)
			err2 := ls.SetWithContext(secretRootCACert, certCopy, expiresAt, false, "token", "locksmith-ca", "", nil)

			pqcErr := error(nil)
			if len(newCA.PQCKeyPEM) > 0 {
				pqcKeyCopy := append([]byte(nil), newCA.PQCKeyPEM...)
				pqcCertCopy := append([]byte(nil), newCA.PQCCertPEM...)
				pqcErr1 := ls.SetWithContext(secretRootPQCKey, pqcKeyCopy, expiresAt, globalBiometricReqs, "token", "locksmith-ca", "", nil)
				pqcErr2 := ls.SetWithContext(secretRootPQCCert, pqcCertCopy, expiresAt, false, "token", "locksmith-ca", "", nil)
				if pqcErr1 != nil {
					pqcErr = pqcErr1
				} else if pqcErr2 != nil {
					pqcErr = pqcErr2
				}
			}

			if err1 == nil && err2 == nil && pqcErr == nil {
				enclaveSealed = true
			}
		}

		if !enclaveSealed {
			if !caAllowUnsealedDiskKeys {
				return errors.New("fatal: failed to seal Root CA private keys in platform enclave (macOS Keychain). Refusing to store unsealed private keys on disk. Pass --allow-unsealed-disk-keys to explicitly opt-in for headless or container environments")
			}
			// Explicit opt-in for unsealed disk keys
			if err := writeKeyFileAtomic(rootKeyPath, newCA.KeyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write %s: %w", rootKeyPath, err)
			}
			if len(newCA.PQCKeyPEM) > 0 {
				if err := writeKeyFileAtomic(pqcKeyPath, newCA.PQCKeyPEM, 0600); err != nil {
					return fmt.Errorf("failed to write %s: %w", pqcKeyPath, err)
				}
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  SECURITY WARNING: Root CA private keys written to unsealed disk storage (%s).\n", rootKeyPath)
		} else {
			// Clean up any stale plaintext keys on disk
			if err := os.Remove(rootKeyPath); err != nil && !os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed cleaning up %s: %v\n", rootKeyPath, err)
			}
			if err := os.Remove(pqcKeyPath); err != nil && !os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed cleaning up %s: %v\n", pqcKeyPath, err)
			}
		}

		classicalFingerprint := sha256.Sum256(newCA.Certificate.Raw)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully initialized Sovereign Dual-Root CA:\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   1. Classical Root (ECDSA P-256):\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Subject:     %s\n", newCA.Certificate.Subject.CommonName)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Valid Until: %s (%d days)\n", newCA.Certificate.NotAfter.Format(time.RFC822), caDays)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Fingerprint: %X\n", classicalFingerprint)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Cert Path:   %s\n", rootCertPath)

		if newCA.PQCCertificate != nil {
			pqcFingerprint := sha256.Sum256(newCA.PQCCertificate.Raw)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   2. Post-Quantum Root (ML-DSA-65 / NIST FIPS 204):\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Subject:     %s\n", newCA.PQCCertificate.Subject.CommonName)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Algorithm:   ML-DSA-65 (Lattice-based Dilithium)\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Fingerprint: %X\n", pqcFingerprint)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Cert Path:   %s\n", pqcCertPath)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Dual Bundle:    %s\n", dualCertPath)

		if caAutoTrust {
			if err := ca.TrustInSystemTrustStore(rootCertPath); err != nil {
				return fmt.Errorf("failed to install cert in trust store: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "✔ Classical Root CA successfully trusted in macOS system trust store.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\n👉 To trust this CA system-wide in macOS, run:\n   locksmith ca trust")
		}

		return nil
	},
}

var caIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue dual TLS server, client, or ephemeral SPIFFE SVID certificates (ECDSA + ML-DSA-65) signed by the Root CA",
	Long: `Generate and sign X.509 certificates using the sovereign Dual-Root CA.
Produces both classical ECDSA and post-quantum ML-DSA-65 certificates.
Defaults to generating server certificates for 127.0.0.1 and localhost.
Use --client to issue mTLS agent authentication certificates.
Use --spiffe to issue short-lived ephemeral SPIFFE X.509-SVIDs (with --ttl).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		certsDir := getDefaultCertsDir()
		if err := os.MkdirAll(certsDir, 0700); err != nil {
			return fmt.Errorf("failed to create certs directory %s: %w", certsDir, err)
		}

		var bundle *ca.IssuedCertBundle
		var certType, baseName string

		if caSpiffeID != "" {
			certType = "SPIFFE SVID"
			spiffeID, err := ca.ParseSPIFFEID(caSpiffeID)
			if err != nil {
				return fmt.Errorf("invalid --spiffe argument: %w", err)
			}
			pathParts := strings.Split(strings.Trim(spiffeID.Path(), "/"), "/")
			baseName = "svid"
			if len(pathParts) > 0 && pathParts[len(pathParts)-1] != "" {
				baseName = fmt.Sprintf("svid-%s", pathParts[len(pathParts)-1])
			}

			profile := &ca.SVIDProfile{
				SPIFFEID: spiffeID,
				Hosts:    caServerHosts,
				TTL:      caTTL,
			}
			bundle, err = rootCA.IssueDualSVID(profile)
			if err != nil {
				return fmt.Errorf("failed to issue dual SPIFFE SVID certificates: %w", err)
			}
		} else if caIsClient {
			certType = "client"
			if caClientName == "" {
				caClientName = "agent-client"
			}
			baseName = caClientName
			bundle, err = rootCA.IssueDualClientCert(caClientName, caDays)
			if err != nil {
				return fmt.Errorf("failed to issue dual client certificates: %w", err)
			}
		} else {
			certType = "server"
			baseName = "server"
			if len(caServerHosts) == 0 {
				caServerHosts = []string{"127.0.0.1", "localhost"}
			}
			bundle, err = rootCA.IssueDualServerCert(caServerHosts, caDays)
			if err != nil {
				return fmt.Errorf("failed to issue dual server certificates: %w", err)
			}
		}

		outCert := caOutCert
		if outCert == "" {
			outCert = filepath.Join(certsDir, fmt.Sprintf("%s.crt", baseName))
		}
		outKey := caOutKey
		if outKey == "" {
			outKey = filepath.Join(certsDir, fmt.Sprintf("%s.key", baseName))
		}

		pqcCertPath := filepath.Join(certsDir, fmt.Sprintf("%s-pqc.crt", baseName))
		pqcKeyPath := filepath.Join(certsDir, fmt.Sprintf("%s-pqc.key", baseName))
		dualCertPath := filepath.Join(certsDir, fmt.Sprintf("%s-dual.crt", baseName))

		// Write classical certs
		if err := os.WriteFile(outCert, bundle.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificate to %s: %w", outCert, err)
		}
		if err := os.WriteFile(outKey, bundle.KeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key to %s: %w", outKey, err)
		}

		// Write PQC certs if generated
		if len(bundle.PQCCertPEM) > 0 {
			_ = os.WriteFile(pqcCertPath, bundle.PQCCertPEM, 0644)
			_ = os.WriteFile(pqcKeyPath, bundle.PQCKeyPEM, 0600)
		}
		if len(bundle.DualCertPEM) > 0 {
			_ = os.WriteFile(dualCertPath, bundle.DualCertPEM, 0644)
		}

		if caSpiffeID != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully issued dual %s certificates:\n", certType)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   SPIFFE ID:          %s\n", caSpiffeID)
			ttlDisplay := caTTL
			if ttlDisplay <= 0 {
				ttlDisplay = ca.DefaultSVIDTTL
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Validity (TTL):     %s\n", ttlDisplay)
			if len(caServerHosts) > 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   SANs:               %s\n", strings.Join(caServerHosts, ", "))
			}
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully issued dual %s certificates (valid %d days):\n", certType, caDays)
			if !caIsClient {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   SANs:               %s\n", strings.Join(caServerHosts, ", "))
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Identity:           %s\n", caClientName)
			}
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Classical Cert:     %s\n", outCert)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Classical Key:      %s\n", outKey)
		if len(bundle.PQCCertPEM) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Post-Quantum Cert:  %s (ML-DSA-65)\n", pqcCertPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Post-Quantum Key:   %s\n", pqcKeyPath)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Dual Bundle:        %s\n", dualCertPath)

		return nil
	},
}

var caTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Install or remove the Classical Root CA from the macOS trust store",
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCertPath := filepath.Join(getDefaultCADir(), "root-ca.crt")
		if _, err := os.Stat(rootCertPath); os.IsNotExist(err) {
			return fmt.Errorf("Root CA not found at %s. Run 'locksmith ca init' first", rootCertPath)
		}

		if caUntrust {
			if err := ca.UntrustFromSystemTrustStore(rootCertPath); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "✔ Successfully removed Root CA from macOS trust store.")
		} else {
			certBytes, err := os.ReadFile(rootCertPath)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(certBytes)
			if block == nil {
				return errors.New("failed decoding Root CA PEM certificate")
			}
			parsedCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed parsing Root CA certificate: %w", err)
			}
			if err := validateRootSecurityProfile(parsedCert); err != nil && !caForceUnconstrained {
				return fmt.Errorf("security violation: refusing to install Root CA into macOS system trust store: %w. Run 'locksmith ca init' to generate a properly constrained root, or pass --force-unconstrained to override", err)
			}

			if err := ca.TrustInSystemTrustStore(rootCertPath); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "✔ Successfully installed and trusted Root CA in macOS trust store.")
		}

		return nil
	},
}

var caStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display Dual-Root CA status, expiration, and fingerprints",
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		classicalFingerprint := sha256.Sum256(rootCA.Certificate.Raw)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "💎 Sovereign Dual-Root Certificate Authority Status:")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   1. Classical Root (ECDSA P-256):\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Common Name:  %s\n", rootCA.Certificate.Subject.CommonName)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Organization: %s\n", strings.Join(rootCA.Certificate.Subject.Organization, ", "))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Valid From:   %s\n", rootCA.Certificate.NotBefore.Format(time.RFC822))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Expires:      %s\n", rootCA.Certificate.NotAfter.Format(time.RFC822))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Fingerprint:  %X\n", classicalFingerprint)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Cert Path:    %s\n", filepath.Join(getDefaultCADir(), "root-ca.crt"))

		if rootCA.PQCCertificate != nil {
			pqcFingerprint := sha256.Sum256(rootCA.PQCCertificate.Raw)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   2. Post-Quantum Root (ML-DSA-65 / NIST FIPS 204):\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Common Name:  %s\n", rootCA.PQCCertificate.Subject.CommonName)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Algorithm:    ML-DSA-65\n")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Fingerprint:  %X\n", pqcFingerprint)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Cert Path:    %s\n", filepath.Join(getDefaultCADir(), "root-ca-pqc.crt"))
		}

		dualPath := filepath.Join(getDefaultCADir(), "root-ca-dual.crt")
		if _, err := os.Stat(dualPath); err == nil {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Dual Bundle:     %s\n", dualPath)
		}

		return nil
	},
}

var caContainerExportCmd = &cobra.Command{
	Use:     "container-export",
	Aliases: []string{"export"},
	Short:   "Export short-lived container certificates and trust bundles for Docker, Envoy, or K3s",
	Long: `Generate and atomically export short-lived X.509 SVID certificates into a container mount directory.
Enforces strict 0700 directory permissions and 0600 private key permissions.
Supports atomic rotation and background auto-renewal with --renew.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if caExportOutDir == "" {
			return errors.New("--out-dir is required for container-export")
		}

		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		var spiffeID *ca.SPIFFEID
		if caSpiffeID != "" {
			spiffeID, err = ca.ParseSPIFFEID(caSpiffeID)
			if err != nil {
				return fmt.Errorf("invalid --spiffe argument: %w", err)
			}
		} else {
			defaultName := caExportName
			if defaultName == "" {
				defaultName = "workload"
			}
			spiffeID, _ = ca.ParseSPIFFEID(fmt.Sprintf("spiffe://bonjoski.local/ns/dev/sa/%s", defaultName))
		}

		profile := &ca.SVIDProfile{
			SPIFFEID: spiffeID,
			Hosts:    caServerHosts,
			TTL:      caTTL,
		}

		opts := &ca.ExportOptions{
			OutDir:  caExportOutDir,
			Format:  ca.ExportFormat(caExportFormat),
			Name:    caExportName,
			Profile: profile,
		}

		if err := rootCA.ExportContainerCerts(opts); err != nil {
			return fmt.Errorf("container export failed: %w", err)
		}

		files, _ := ca.ResolveFilenames(opts.Format, opts.Name)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully exported container certificates (%s format):\n", opts.Format)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Directory:   %s (0700)\n", opts.OutDir)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Certificate: %s\n", filepath.Join(opts.OutDir, files.CertName))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Private Key: %s (0600)\n", filepath.Join(opts.OutDir, files.KeyName))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Trust Root:  %s\n", filepath.Join(opts.OutDir, files.CAName))

		if caExportRenew {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "🔄 Starting background auto-renewal loop (renewing at half TTL)...\n")
			stopCh := make(chan struct{})
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigCh
				close(stopCh)
			}()

			return rootCA.AutoRotateLoop(opts, stopCh, func() {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✔ [%s] Ephemeral SVID certificates atomically rotated in %s\n", time.Now().Format("15:04:05"), opts.OutDir)
			})
		}

		return nil
	},
}

func resolveBridgeKey() ([]byte, error) {
	if caServeBridgeKeyFile != "" {
		data, err := os.ReadFile(caServeBridgeKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading bridge key file %s: %w", caServeBridgeKeyFile, err)
		}
		return data, nil
	}
	if envKey := os.Getenv("LOCKSMITH_BRIDGE_KEY"); envKey != "" {
		if decoded, err := hex.DecodeString(strings.TrimSpace(envKey)); err == nil {
			return decoded, nil
		}
		return []byte(envKey), nil
	}
	return nil, nil
}

func resolveBridgeCredentials() (string, []byte, error) {
	bridgeToken := caServeBridgeToken
	if bridgeToken == "" && caServeBridgeTokenFile != "" {
		data, err := os.ReadFile(caServeBridgeTokenFile)
		if err != nil {
			return "", nil, fmt.Errorf("failed reading bridge token file %s: %w", caServeBridgeTokenFile, err)
		}
		bridgeToken = strings.TrimSpace(string(data))
	}
	if bridgeToken == "" {
		bridgeToken = os.Getenv("LOCKSMITH_BRIDGE_TOKEN")
	}

	bridgeKey, err := resolveBridgeKey()
	if err != nil {
		return "", nil, err
	}
	if len(bridgeKey) > 0 && len(bridgeKey) < 32 {
		return "", nil, errors.New("bridge master key must be at least 32 bytes")
	}
	return bridgeToken, bridgeKey, nil
}

func saveAndLogBridgeSecrets(cmd *cobra.Command, ws *spiffe.WorkloadServer, allowedCIDs []uint32, vsockPort uint32, noPersist bool) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   VSock Bridge: 127.0.0.1:%d (Allowed CIDs: %v)\n", vsockPort, allowedCIDs)
	if noPersist {
		return
	}
	caDir := getDefaultCADir()
	if err := os.MkdirAll(caDir, 0700); err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  Failed to create CA directory %s: %v\n", caDir, err)
		return
	}
	if len(ws.BridgeKey()) > 0 {
		keyPath := filepath.Join(caDir, "bridge.key")
		if err := writeKeyFileAtomic(keyPath, ws.BridgeKey(), 0600); err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  Failed writing bridge key to %s: %v\n", keyPath, err)
		} else {
			keyFp := sha256.Sum256(ws.BridgeKey())
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "   Bridge Key:   Saved to %s (SHA-256: %x...)\n", keyPath, keyFp[:6])
		}
	}
	if ws.BridgeToken() != "" {
		tokenPath := filepath.Join(caDir, "bridge.token")
		if err := writeKeyFileAtomic(tokenPath, []byte(ws.BridgeToken()+"\n"), 0600); err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  Failed writing bridge token to %s: %v\n", tokenPath, err)
		} else {
			tokenFp := sha256.Sum256([]byte(ws.BridgeToken()))
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "   Bridge Token: Saved to %s (SHA-256: %x...)\n", tokenPath, tokenFp[:6])
		}
	}
	for _, cid := range allowedCIDs {
		derived := ws.DeriveBridgeToken(cid)
		if derived != "" && derived != ws.BridgeToken() {
			cidTokenPath := filepath.Join(caDir, fmt.Sprintf("bridge-cid-%d.token", cid))
			_ = writeKeyFileAtomic(cidTokenPath, []byte(derived+"\n"), 0600)
		}
	}
}

var caDeriveBridgeTokenCmd = &cobra.Command{
	Use:   "derive-bridge-token",
	Short: "Derive an authoritative bridge authentication token for a microVM CID",
	Long: `Derive a domain-separated bridge token for an Aegisbox microVM CID using HKDF-SHA256.
Enables dynamic provisioning of subagent microVMs without restarting the SPIFFE daemon.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if caDeriveCID < 3 {
			return fmt.Errorf("invalid microVM CID %d: must be >= 3", caDeriveCID)
		}
		var keyBytes []byte
		if caDeriveKeyFile != "" {
			data, err := os.ReadFile(caDeriveKeyFile)
			if err != nil {
				return fmt.Errorf("failed reading bridge key file %s: %w", caDeriveKeyFile, err)
			}
			keyBytes = data
		} else {
			caDir := getDefaultCADir()
			defaultKeyPath := filepath.Join(caDir, "bridge.key")
			if data, err := os.ReadFile(defaultKeyPath); err == nil {
				keyBytes = data
			} else if envKey := os.Getenv("LOCKSMITH_BRIDGE_KEY"); envKey != "" {
				if decoded, err := hex.DecodeString(strings.TrimSpace(envKey)); err == nil {
					keyBytes = decoded
				} else {
					keyBytes = []byte(envKey)
				}
			}
		}
		if len(keyBytes) == 0 {
			return errors.New("no bridge key found; specify --key-file, set LOCKSMITH_BRIDGE_KEY, or run 'locksmith ca serve-spiffe' first")
		}
		deriver, err := spiffe.NewBridgeTokenDeriver(keyBytes)
		if err != nil {
			return fmt.Errorf("invalid bridge key: %w", err)
		}
		token := deriver.DeriveToken(caDeriveCID)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), token)
		return nil
	},
}

var caServeSpiffeCmd = &cobra.Command{
	Use:   "serve-spiffe",
	Short: "Start the sovereign SPIFFE Workload API Unix domain socket daemon",
	Long: `Start the local SPIFFE Workload API daemon listening on a Unix domain socket.
Provides zero-dependency X.509-SVID issuance and attestation for local developer containers,
microservices, and Aegisbox microVMs with kernel-level peer attestation (Darwin LOCAL_PEERCRED, Linux SO_PEERCRED).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		if caServeTrustDomain == "" {
			caServeTrustDomain = spiffe.DefaultTrustDomain
		}

		pol, err := spiffe.LoadPolicy(caServePolicyPath, caServeTrustDomain)
		if err != nil {
			return fmt.Errorf("failed loading spiffe policy: %w", err)
		}

		for _, warn := range pol.Warnings() {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  SPIFFE Policy Warning: %s\n", warn)
		}

		for _, cid := range caServeAllowedCIDs {
			pol.AllowedCIDs = append(pol.AllowedCIDs, uint32(cid))
		}

		if caServeVsockPort > 0 && len(pol.AllowedCIDs) == 0 {
			return errors.New("fatal: --vsock-port requires at least one allowed microVM CID configured in policy.json or via --allowed-cid")
		}

		bridgeToken, bridgeKey, err := resolveBridgeCredentials()
		if err != nil {
			return err
		}

		ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
			SocketPath:  caServeSocket,
			VsockPort:   caServeVsockPort,
			BridgeToken: bridgeToken,
			BridgeKey:   bridgeKey,
			TrustDomain: caServeTrustDomain,
			Policy:      pol,
			CA:          rootCA,
			RateLimit:   rate.Limit(caServeRateLimit),
		})
		if err != nil {
			return fmt.Errorf("failed creating workload server: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Starting Sovereign SPIFFE Workload API Server...\n")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Trust Domain: %s\n", caServeTrustDomain)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Socket Path:  %s (0600)\n", ws.SocketPath())
		if caServeVsockPort > 0 {
			saveAndLogBridgeSecrets(cmd, ws, pol.AllowedCIDs, caServeVsockPort, caServeNoPersistBridgeKey)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Rate Limit:   %.0f req/s per UID\n", caServeRateLimit)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

		go func() {
			<-sigCh
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nShutting down SPIFFE Workload API server...")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = ws.Stop(ctx)
		}()

		if err := ws.Start(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}

		return nil
	},
}

func getKeychainSecretPEM(key string) []byte {
	if ls == nil {
		return nil
	}
	secret, err := ls.GetWithMetadata(key)
	if err != nil || len(secret.Value) == 0 {
		return nil
	}
	if block, _ := pem.Decode(secret.Value); block != nil {
		return append([]byte(nil), secret.Value...)
	}
	return nil
}

func readCADiskFile(path string, required bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if required {
			return nil, fmt.Errorf("Root CA file not found at %s. Please run 'locksmith ca init' first", path)
		}
		return nil, nil
	}
	return data, nil
}

func loadRootCA() (*ca.CA, error) {
	certData := getKeychainSecretPEM(secretRootCACert)
	keyData := getKeychainSecretPEM(secretRootCAKey)
	pqcCertData := getKeychainSecretPEM(secretRootPQCCert)
	pqcKeyData := getKeychainSecretPEM(secretRootPQCKey)

	caDir := getDefaultCADir()
	var err error
	if len(certData) == 0 {
		certData, err = readCADiskFile(filepath.Join(caDir, "root-ca.crt"), true)
		if err != nil {
			return nil, err
		}
	}
	if len(keyData) == 0 {
		keyPath := filepath.Join(caDir, "root-ca.key")
		keyData, err = readCADiskFile(keyPath, true)
		if err != nil {
			return nil, err
		}
		_, _ = fmt.Fprintf(os.Stderr, "⚠️  SECURITY WARNING: Root CA private key loaded from unsealed disk storage (%s).\n", keyPath)
	}
	if len(pqcCertData) == 0 {
		pqcCertData, _ = readCADiskFile(filepath.Join(caDir, "root-ca-pqc.crt"), false)
	}
	if len(pqcKeyData) == 0 {
		pqcKeyData, _ = readCADiskFile(filepath.Join(caDir, "root-ca-pqc.key"), false)
	}

	return ca.LoadDualCA(certData, keyData, pqcCertData, pqcKeyData)
}

func init() {
	rootCmd.AddCommand(caCmd)
	caCmd.PersistentFlags().StringVar(&caCustomCADir, "ca-dir", "", "Custom CA directory (defaults to ~/.locksmith/ca or LOCKSMITH_CA_DIR)")
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caIssueCmd)
	caCmd.AddCommand(caTrustCmd)
	caCmd.AddCommand(caStatusCmd)
	caCmd.AddCommand(caContainerExportCmd)
	caCmd.AddCommand(caServeSpiffeCmd)
	caCmd.AddCommand(caDeriveBridgeTokenCmd)

	// ca derive-bridge-token flags
	caDeriveBridgeTokenCmd.Flags().Uint32Var(&caDeriveCID, "cid", 0, "Target Aegisbox microVM CID (required, >= 3)")
	_ = caDeriveBridgeTokenCmd.MarkFlagRequired("cid")
	caDeriveBridgeTokenCmd.Flags().StringVar(&caDeriveKeyFile, "key-file", "", "Path to bridge master HMAC key file")

	// ca init flags
	caInitCmd.Flags().StringVar(&caCommonName, "common-name", ca.DefaultCAName, "Common Name for the Root CA")
	caInitCmd.Flags().StringVar(&caOrg, "org", ca.DefaultCAOrganization, "Organization name for the Root CA")
	caInitCmd.Flags().IntVar(&caDays, "days", ca.DefaultCAValidityDays, "Validity duration in days for the Root CA")
	caInitCmd.Flags().BoolVar(&caAutoTrust, "trust", false, "Automatically install the Classical Root CA into the macOS system trust store")
	caInitCmd.Flags().BoolVar(&caAllowUnsealedDiskKeys, "allow-unsealed-disk-keys", false, "Allow storing unsealed plaintext root keys on disk (for headless/CI environments)")
	caInitCmd.Flags().StringSliceVar(&caPermittedDNS, "permitted-dns", nil, "Permitted DNS domains for RFC 5280 Name Constraints (e.g. localhost,.localhost)")
	caInitCmd.Flags().StringSliceVar(&caPermittedIP, "permitted-ip", nil, "Permitted IP ranges for RFC 5280 Name Constraints (e.g. 127.0.0.0/8,::1/128)")
	caInitCmd.Flags().StringSliceVar(&caPermittedURI, "permitted-uri", nil, "Permitted URI domains for RFC 5280 Name Constraints (e.g. bonjoski.local)")
	caInitCmd.Flags().BoolVar(&caAllowBroadDomains, "allow-broad-domains", false, "Allow broad private TLDs (.local / .internal) in Name Constraints")

	// ca issue flags
	caIssueCmd.Flags().StringSliceVar(&caServerHosts, "domain", []string{"127.0.0.1", "localhost"}, "Domain names and IP addresses for the server certificate")
	caIssueCmd.Flags().BoolVar(&caIsClient, "client", false, "Issue a client certificate for mutual TLS (mTLS)")
	caIssueCmd.Flags().StringVar(&caClientName, "name", "agent-client", "Client identity name for mTLS certificate")
	caIssueCmd.Flags().IntVar(&caDays, "days", ca.DefaultCertValidity, "Validity duration in days for the issued certificate")
	caIssueCmd.Flags().StringVar(&caOutCert, "out-cert", "", "Output path for the certificate file")
	caIssueCmd.Flags().StringVar(&caOutKey, "out-key", "", "Output path for the private key file")
	caIssueCmd.Flags().StringVar(&caSpiffeID, "spiffe", "", "Issue an ephemeral SPIFFE X.509-SVID (e.g. spiffe://bonjoski.local/ns/dev/sa/api)")
	caIssueCmd.Flags().DurationVar(&caTTL, "ttl", 0, "Ephemeral certificate validity duration (e.g. 15m, 1h, 24h)")

	// ca trust flags
	caTrustCmd.Flags().BoolVar(&caUntrust, "untrust", false, "Remove the Classical Root CA from the macOS trust store")
	caTrustCmd.Flags().BoolVar(&caForceUnconstrained, "force-unconstrained", false, "Force installing a Root CA into trust store even if it lacks RFC 5280 Name Constraints")

	// ca container-export flags
	caContainerExportCmd.Flags().StringVar(&caExportOutDir, "out-dir", "", "Target directory for exported container certificates (required)")
	caContainerExportCmd.Flags().StringVar(&caExportFormat, "format", "docker", "Export format: docker, envoy, or k3s")
	caContainerExportCmd.Flags().StringVar(&caExportName, "name", "", "Workload service name for file naming (e.g. backend)")
	caContainerExportCmd.Flags().StringVar(&caSpiffeID, "spiffe", "", "SPIFFE ID for the workload certificate")
	caContainerExportCmd.Flags().DurationVar(&caTTL, "ttl", ca.DefaultSVIDTTL, "Ephemeral certificate validity duration (e.g. 15m, 1h, 2h)")
	caContainerExportCmd.Flags().StringSliceVar(&caServerHosts, "domain", nil, "Optional SAN domain names and IP addresses")
	caContainerExportCmd.Flags().BoolVar(&caExportRenew, "renew", false, "Run background auto-renewal loop to refresh certs at half-TTL")

	// ca serve-spiffe flags
	caServeSpiffeCmd.Flags().StringVar(&caServeSocket, "socket", "", "Socket path for the Workload API (default ~/.locksmith/spiffe/workload.sock)")
	caServeSpiffeCmd.Flags().Uint32Var(&caServeVsockPort, "vsock-port", 0, "Optional vsock port for Aegisbox microVM attestation (e.g. 9099)")
	caServeSpiffeCmd.Flags().StringVar(&caServeTrustDomain, "trust-domain", spiffe.DefaultTrustDomain, "Sovereign trust domain authority")
	caServeSpiffeCmd.Flags().StringVar(&caServePolicyPath, "policy", "", "Path to local policy.json file")
	caServeSpiffeCmd.Flags().Float64Var(&caServeRateLimit, "rate-limit", 10.0, "Attestation rate limit (requests per second per UID)")
	caServeSpiffeCmd.Flags().StringVar(&caServeBridgeToken, "bridge-token", "", "Pre-shared authorization token for loopback TCP vsock bridge")
	_ = caServeSpiffeCmd.Flags().MarkDeprecated("bridge-token", "use --bridge-token-file or LOCKSMITH_BRIDGE_TOKEN instead to avoid argument leaking in ps")
	caServeSpiffeCmd.Flags().StringVar(&caServeBridgeTokenFile, "bridge-token-file", "", "Path to file containing pre-shared bridge token")
	caServeSpiffeCmd.Flags().StringVar(&caServeBridgeKeyFile, "bridge-key-file", "", "Path to file containing 32-byte master HMAC bridge key")
	caServeSpiffeCmd.Flags().UintSliceVar(&caServeAllowedCIDs, "allowed-cid", nil, "Allowed microVM CIDs for vsock bridge")
	caServeSpiffeCmd.Flags().BoolVar(&caServeNoPersistBridgeKey, "no-persist-bridge-key", false, "Do not write bridge key or bridge tokens to disk")
}
