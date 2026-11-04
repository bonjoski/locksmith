package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
	caExportRenew      bool
	caServeSocket      string
	caServeTrustDomain string
	caServePolicyPath        string
	caServeRateLimit         float64
	caServeVsockPort         uint32
	caAllowUnsealedDiskKeys  bool
	caForceUnconstrained     bool
	caServeBridgeToken       string
	caServeAllowedCIDs       []uint
)

const (
	secretRootCAKey   = "ca:root:key"
	secretRootCACert  = "ca:root:cert"
	secretRootPQCKey  = "ca:root:pqc:key"
	secretRootPQCCert = "ca:root:pqc:cert"
)

func getDefaultCADir() string {
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

		// Generate Dual Root CA (ECDSA + ML-DSA-65)
		newCA, err := ca.GenerateRootCA(caCommonName, caOrg, caDays)
		if err != nil {
			return fmt.Errorf("failed to generate Dual Root CA: %w", err)
		}

		// 1. Write public certificates with standard read permissions
		if err := os.WriteFile(rootCertPath, newCA.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootCertPath, err)
		}
		if len(newCA.PQCCertPEM) > 0 {
			if err := os.WriteFile(pqcCertPath, newCA.PQCCertPEM, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", pqcCertPath, err)
			}
		}
		if len(newCA.DualCertPEM) > 0 {
			if err := os.WriteFile(dualCertPath, newCA.DualCertPEM, 0644); err != nil {
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
			if err := os.WriteFile(rootKeyPath, newCA.KeyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write %s: %w", rootKeyPath, err)
			}
			if len(newCA.PQCKeyPEM) > 0 {
				if err := os.WriteFile(pqcKeyPath, newCA.PQCKeyPEM, 0600); err != nil {
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
			if len(parsedCert.PermittedDNSDomains) == 0 && !caForceUnconstrained {
				return errors.New("security violation: refusing to install Root CA into macOS system trust store because it lacks RFC 5280 Name Constraints. Run 'locksmith ca init' to generate a name-constrained root, or pass --force-unconstrained to override")
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

		for _, cid := range caServeAllowedCIDs {
			pol.AllowedCIDs = append(pol.AllowedCIDs, uint32(cid))
		}

		if caServeVsockPort > 0 && len(pol.AllowedCIDs) == 0 {
			return errors.New("fatal: --vsock-port requires at least one allowed microVM CID configured in policy.json or via --allowed-cid")
		}

		ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
			SocketPath:  caServeSocket,
			VsockPort:   caServeVsockPort,
			BridgeToken: caServeBridgeToken,
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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   VSock Bridge: 127.0.0.1:%d (Allowed CIDs: %v)\n", caServeVsockPort, pol.AllowedCIDs)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Bridge Token: %s\n", ws.BridgeToken())
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
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caIssueCmd)
	caCmd.AddCommand(caTrustCmd)
	caCmd.AddCommand(caStatusCmd)
	caCmd.AddCommand(caContainerExportCmd)
	caCmd.AddCommand(caServeSpiffeCmd)

	// ca init flags
	caInitCmd.Flags().StringVar(&caCommonName, "common-name", ca.DefaultCAName, "Common Name for the Root CA")
	caInitCmd.Flags().StringVar(&caOrg, "org", ca.DefaultCAOrganization, "Organization name for the Root CA")
	caInitCmd.Flags().IntVar(&caDays, "days", ca.DefaultCAValidityDays, "Validity duration in days for the Root CA")
	caInitCmd.Flags().BoolVar(&caAutoTrust, "trust", false, "Automatically install the Classical Root CA into the macOS system trust store")
	caInitCmd.Flags().BoolVar(&caAllowUnsealedDiskKeys, "allow-unsealed-disk-keys", false, "Allow storing unsealed plaintext root keys on disk (for headless/CI environments)")

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
	caServeSpiffeCmd.Flags().UintSliceVar(&caServeAllowedCIDs, "allowed-cid", nil, "Allowed microVM CIDs for vsock bridge")
}
