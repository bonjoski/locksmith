package cmd

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/spf13/cobra"
)

var (
	caCommonName  string
	caOrg         string
	caDays        int
	caAutoTrust   bool
	caServerHosts []string
	caClientName  string
	caIsClient    bool
	caOutCert     string
	caOutKey      string
	caUntrust     bool
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

		// Write files with strict permissions
		if err := os.WriteFile(rootCertPath, newCA.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootCertPath, err)
		}
		if err := os.WriteFile(rootKeyPath, newCA.KeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootKeyPath, err)
		}
		if len(newCA.PQCCertPEM) > 0 {
			if err := os.WriteFile(pqcCertPath, newCA.PQCCertPEM, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", pqcCertPath, err)
			}
			if err := os.WriteFile(pqcKeyPath, newCA.PQCKeyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write %s: %w", pqcKeyPath, err)
			}
		}
		if len(newCA.DualCertPEM) > 0 {
			if err := os.WriteFile(dualCertPath, newCA.DualCertPEM, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", dualCertPath, err)
			}
		}

		// Save Root Keys & Certs to Locksmith Enclave
		if ls != nil {
			expiresAt := time.Now().Add(time.Duration(caDays) * 24 * time.Hour)
			keyCopy := append([]byte(nil), newCA.KeyPEM...)
			certCopy := append([]byte(nil), newCA.CertPEM...)
			_ = ls.SetWithContext(secretRootCAKey, keyCopy, expiresAt, globalBiometricReqs, "token", "locksmith-ca", "", nil)
			_ = ls.SetWithContext(secretRootCACert, certCopy, expiresAt, false, "token", "locksmith-ca", "", nil)

			if len(newCA.PQCKeyPEM) > 0 {
				pqcKeyCopy := append([]byte(nil), newCA.PQCKeyPEM...)
				pqcCertCopy := append([]byte(nil), newCA.PQCCertPEM...)
				_ = ls.SetWithContext(secretRootPQCKey, pqcKeyCopy, expiresAt, globalBiometricReqs, "token", "locksmith-ca", "", nil)
				_ = ls.SetWithContext(secretRootPQCCert, pqcCertCopy, expiresAt, false, "token", "locksmith-ca", "", nil)
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
	Short: "Issue dual TLS server or client certificates (ECDSA + ML-DSA-65) signed by the Root CA",
	Long: `Generate and sign X.509 certificates using the sovereign Dual-Root CA.
Produces both classical ECDSA and post-quantum ML-DSA-65 certificates.
Defaults to generating server certificates for 127.0.0.1 and localhost.
Use --client to issue mTLS agent authentication certificates.`,
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

		if caIsClient {
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

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully issued dual %s certificates (valid %d days):\n", certType, caDays)
		if !caIsClient {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   SANs:               %s\n", strings.Join(caServerHosts, ", "))
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Identity:           %s\n", caClientName)
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
		keyData, err = readCADiskFile(filepath.Join(caDir, "root-ca.key"), true)
		if err != nil {
			return nil, err
		}
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

	// ca init flags
	caInitCmd.Flags().StringVar(&caCommonName, "common-name", ca.DefaultCAName, "Common Name for the Root CA")
	caInitCmd.Flags().StringVar(&caOrg, "org", ca.DefaultCAOrganization, "Organization name for the Root CA")
	caInitCmd.Flags().IntVar(&caDays, "days", ca.DefaultCAValidityDays, "Validity duration in days for the Root CA")
	caInitCmd.Flags().BoolVar(&caAutoTrust, "trust", false, "Automatically install the Classical Root CA into the macOS system trust store")

	// ca issue flags
	caIssueCmd.Flags().StringSliceVar(&caServerHosts, "domain", []string{"127.0.0.1", "localhost"}, "Domain names and IP addresses for the server certificate")
	caIssueCmd.Flags().BoolVar(&caIsClient, "client", false, "Issue a client certificate for mutual TLS (mTLS)")
	caIssueCmd.Flags().StringVar(&caClientName, "name", "agent-client", "Client identity name for mTLS certificate")
	caIssueCmd.Flags().IntVar(&caDays, "days", ca.DefaultCertValidity, "Validity duration in days for the issued certificate")
	caIssueCmd.Flags().StringVar(&caOutCert, "out-cert", "", "Output path for the certificate file")
	caIssueCmd.Flags().StringVar(&caOutKey, "out-key", "", "Output path for the private key file")

	// ca trust flags
	caTrustCmd.Flags().BoolVar(&caUntrust, "untrust", false, "Remove the Classical Root CA from the macOS trust store")
}
