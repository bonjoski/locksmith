package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/spf13/cobra"
)

var (
	caCommonName   string
	caOrg          string
	caDays         int
	caAutoTrust    bool
	caServerHosts  []string
	caClientName   string
	caIsClient     bool
	caOutCert      string
	caOutKey       string
	caUntrust      bool
)

const (
	secretRootCAKey  = "ca:root:key"
	secretRootCACert = "ca:root:cert"
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
	Short: "Initialize the sovereign Root Certificate Authority",
	Long: `Generate a new self-signed Root Certificate Authority (CA).
The Root CA private key is securely sealed inside your platform enclave (macOS Keychain with Touch ID).
The public certificate is exported to ~/.locksmith/ca/root-ca.crt.
Use --trust to automatically install the Root CA into the macOS system trust store.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		caDir := getDefaultCADir()
		if err := os.MkdirAll(caDir, 0700); err != nil {
			return fmt.Errorf("failed to create CA directory %s: %w", caDir, err)
		}

		rootCertPath := filepath.Join(caDir, "root-ca.crt")
		rootKeyPath := filepath.Join(caDir, "root-ca.key")

		// Generate Root CA
		newCA, err := ca.GenerateRootCA(caCommonName, caOrg, caDays)
		if err != nil {
			return fmt.Errorf("failed to generate Root CA: %w", err)
		}

		// Write files with 0600 permissions first
		if err := os.WriteFile(rootCertPath, newCA.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootCertPath, err)
		}
		if err := os.WriteFile(rootKeyPath, newCA.KeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", rootKeyPath, err)
		}

		// Save Root Key & Cert copies to Locksmith Enclave (SetWithContext zeroes input in place)
		if ls != nil {
			expiresAt := time.Now().Add(time.Duration(caDays) * 24 * time.Hour)
			keyCopy := append([]byte(nil), newCA.KeyPEM...)
			certCopy := append([]byte(nil), newCA.CertPEM...)
			if err := ls.SetWithContext(secretRootCAKey, keyCopy, expiresAt, globalBiometricReqs, "token", "locksmith-ca", "", nil); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to store CA key in keychain: %v\n", err)
			}
			if err := ls.SetWithContext(secretRootCACert, certCopy, expiresAt, false, "token", "locksmith-ca", "", nil); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to store CA cert in keychain: %v\n", err)
			}
		}

		fingerprint := sha256.Sum256(newCA.Certificate.Raw)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully initialized Root CA: %s\n", newCA.Certificate.Subject.CommonName)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Valid Until: %s (%d days)\n", newCA.Certificate.NotAfter.Format(time.RFC822), caDays)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Fingerprint: %X\n", fingerprint)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Public Cert: %s\n", rootCertPath)

		if caAutoTrust {
			if err := ca.TrustInSystemTrustStore(rootCertPath); err != nil {
				return fmt.Errorf("failed to install cert in trust store: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "✔ Root CA successfully trusted in macOS system trust store.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\n👉 To trust this CA system-wide in macOS, run:\n   locksmith ca trust")
		}

		return nil
	},
}

var caIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a TLS server or client certificate signed by the Root CA",
	Long: `Generate and sign an X.509 certificate using the sovereign Root CA.
Defaults to generating a server certificate for 127.0.0.1 and localhost.
Use --client to issue an mTLS agent authentication certificate.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		certsDir := getDefaultCertsDir()
		if err := os.MkdirAll(certsDir, 0700); err != nil {
			return fmt.Errorf("failed to create certs directory %s: %w", certsDir, err)
		}

		var certPEM, keyPEM []byte
		var certType string

		if caIsClient {
			certType = "client"
			if caClientName == "" {
				caClientName = "agent-client"
			}
			certPEM, keyPEM, err = rootCA.IssueClientCert(caClientName, caDays)
			if err != nil {
				return fmt.Errorf("failed to issue client certificate: %w", err)
			}
			if caOutCert == "" {
				caOutCert = filepath.Join(certsDir, fmt.Sprintf("%s.crt", caClientName))
			}
			if caOutKey == "" {
				caOutKey = filepath.Join(certsDir, fmt.Sprintf("%s.key", caClientName))
			}
		} else {
			certType = "server"
			if len(caServerHosts) == 0 {
				caServerHosts = []string{"127.0.0.1", "localhost"}
			}
			certPEM, keyPEM, err = rootCA.IssueServerCert(caServerHosts, caDays)
			if err != nil {
				return fmt.Errorf("failed to issue server certificate: %w", err)
			}
			if caOutCert == "" {
				caOutCert = filepath.Join(certsDir, "server.crt")
			}
			if caOutKey == "" {
				caOutKey = filepath.Join(certsDir, "server.key")
			}
		}

		if err := os.WriteFile(caOutCert, certPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificate to %s: %w", caOutCert, err)
		}
		if err := os.WriteFile(caOutKey, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key to %s: %w", caOutKey, err)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "💎 Successfully issued %s certificate (valid %d days):\n", certType, caDays)
		if !caIsClient {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   SANs:        %s\n", strings.Join(caServerHosts, ", "))
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Identity:    %s\n", caClientName)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Certificate: %s\n", caOutCert)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Private Key: %s\n", caOutKey)

		return nil
	},
}

var caTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Install or remove the Root CA from the macOS trust store",
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
	Short: "Display Root CA status, expiration, and fingerprints",
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCA, err := loadRootCA()
		if err != nil {
			return err
		}

		fingerprint := sha256.Sum256(rootCA.Certificate.Raw)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "💎 Sovereign Certificate Authority Status:")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Common Name:  %s\n", rootCA.Certificate.Subject.CommonName)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Organization: %s\n", strings.Join(rootCA.Certificate.Subject.Organization, ", "))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Valid From:   %s\n", rootCA.Certificate.NotBefore.Format(time.RFC822))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Expires:      %s\n", rootCA.Certificate.NotAfter.Format(time.RFC822))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Fingerprint:  %X\n", fingerprint)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "   Cert Path:    %s\n", filepath.Join(getDefaultCADir(), "root-ca.crt"))

		return nil
	},
}

func loadRootCA() (*ca.CA, error) {
	// Try loading from Locksmith Keychain first
	if ls != nil {
		certSecret, errCert := ls.GetWithMetadata(secretRootCACert)
		keySecret, errKey := ls.GetWithMetadata(secretRootCAKey)
		if errCert == nil && errKey == nil && len(certSecret.Value) > 0 && len(keySecret.Value) > 0 {
			rootCA, err := ca.LoadCA(certSecret.Value, keySecret.Value)
			certSecret.Zero()
			keySecret.Zero()
			if err == nil {
				return rootCA, nil
			}
		}
	}

	// Fallback to disk files in ~/.locksmith/ca/
	caDir := getDefaultCADir()
	certPath := filepath.Join(caDir, "root-ca.crt")
	keyPath := filepath.Join(caDir, "root-ca.key")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("Root CA certificate not found at %s. Please run 'locksmith ca init' first", certPath)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("Root CA private key not found at %s. Please run 'locksmith ca init' first", keyPath)
	}

	return ca.LoadCA(certData, keyData)
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
	caInitCmd.Flags().BoolVar(&caAutoTrust, "trust", false, "Automatically install the Root CA into the macOS system trust store")

	// ca issue flags
	caIssueCmd.Flags().StringSliceVar(&caServerHosts, "domain", []string{"127.0.0.1", "localhost"}, "Domain names and IP addresses for the server certificate")
	caIssueCmd.Flags().BoolVar(&caIsClient, "client", false, "Issue a client certificate for mutual TLS (mTLS)")
	caIssueCmd.Flags().StringVar(&caClientName, "name", "agent-client", "Client identity name for mTLS certificate")
	caIssueCmd.Flags().IntVar(&caDays, "days", ca.DefaultCertValidity, "Validity duration in days for the issued certificate")
	caIssueCmd.Flags().StringVar(&caOutCert, "out-cert", "", "Output path for the certificate file")
	caIssueCmd.Flags().StringVar(&caOutKey, "out-key", "", "Output path for the private key file")

	// ca trust flags
	caTrustCmd.Flags().BoolVar(&caUntrust, "untrust", false, "Remove the Root CA from the macOS trust store")
}
