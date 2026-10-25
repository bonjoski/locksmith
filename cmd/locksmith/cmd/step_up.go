package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/stepup"
	"github.com/spf13/cobra"
)

var (
	stepUpChallenge string
	stepUpSeverity  string
	stepUpTTL       time.Duration
	stepUpAudience  string
	stepUpRaw       bool
	stepUpVerify    string
	stepUpPubKey    string

	// Mockable for tests
	stepUpAuthenticator stepup.BiometricAuthenticator
)

var stepUpCmd = &cobra.Command{
	Use:     "step-up",
	Aliases: []string{"stepup"},
	Short:   "Trigger a native biometric challenge and issue a signed verification attestation token",
	Long: `Triggers a platform native biometric challenge (Touch ID on macOS via LocalAuthentication,
Windows Hello on Windows via UserConsentVerifier) for step-up authorization,
and outputs a signed cryptographic attestation token on success.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Verification mode
		if stepUpVerify != "" {
			var pubKey ed25519.PublicKey
			if stepUpPubKey != "" {
				pubBytes, err := base64.RawURLEncoding.DecodeString(stepUpPubKey)
				if err != nil {
					return fmt.Errorf("invalid base64url public key: %w", err)
				}
				pubKey = ed25519.PublicKey(pubBytes)
			} else {
				var err error
				pubKey, err = stepup.GetAttestationPublicKey()
				if err != nil {
					return fmt.Errorf("failed to obtain local attestation public key: %w", err)
				}
			}

			verified, err := stepup.Verify(stepUpVerify, pubKey)
			if err != nil {
				return fmt.Errorf("attestation verification failed: %w", err)
			}

			if stepUpRaw {
				fmt.Fprintln(cmd.OutOrStdout(), "VALID")
				return nil
			}

			out, err := json.MarshalIndent(verified, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		}

		// Step-up Challenge mode
		if strings.TrimSpace(stepUpChallenge) == "" {
			return errors.New("--challenge is required (e.g. --challenge=\"Approve raw disk write\")")
		}

		req := stepup.StepUpRequest{
			Challenge: stepUpChallenge,
			Severity:  stepup.NormalizeSeverity(stepUpSeverity),
			TTL:       stepUpTTL,
			Audience:  stepUpAudience,
		}

		var opts []stepup.Option
		if stepUpAuthenticator != nil {
			opts = append(opts, stepup.WithAuthenticator(stepUpAuthenticator))
		}

		token, err := stepup.Authorize(cmd.Context(), req, opts...)
		if err != nil {
			return err
		}

		if stepUpRaw {
			fmt.Fprintln(cmd.OutOrStdout(), token.RawToken)
			return nil
		}

		out, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	},
}

func init() {
	stepUpCmd.Flags().StringVar(&stepUpChallenge, "challenge", "", "Challenge description requiring authorization (e.g. \"Approve raw disk write\")")
	stepUpCmd.Flags().StringVar(&stepUpSeverity, "severity", "CRITICAL", "Severity level (CRITICAL, HIGH, MEDIUM, LOW)")
	stepUpCmd.Flags().DurationVar(&stepUpTTL, "ttl", 5*time.Minute, "Attestation token validity duration (e.g. 5m, 60s)")
	stepUpCmd.Flags().StringVar(&stepUpAudience, "audience", "aegisbox", "Target audience for the attestation token")
	stepUpCmd.Flags().BoolVar(&stepUpRaw, "raw", false, "Output only the raw signed token string for scripting")
	stepUpCmd.Flags().StringVar(&stepUpVerify, "verify", "", "Verify an existing attestation token")
	stepUpCmd.Flags().StringVar(&stepUpPubKey, "pubkey", "", "Base64URL public key for verification (defaults to local attestation key)")

	rootCmd.AddCommand(stepUpCmd)
}
