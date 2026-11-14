package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/assertion"
	"github.com/spf13/cobra"
)

var (
	assertionAudience string
	assertionSubject  string
	assertionNonce    string
	assertionValidity time.Duration
	assertionFormat   string
)

var signAssertionCmd = &cobra.Command{
	Use:   "sign-assertion",
	Short: "Synthesize a hardware-rooted WebAuthn/FIDO2 or RFC 7523 client assertion",
	Long: `Synthesize a short-lived, hardware-enclave-backed client assertion token
(RFC 7523 JWT or WebAuthn assertion) for authentication against cloud IdPs (AWS IAM, GitHub)
without storing static API keys or unencrypted software private keys on disk.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if assertionAudience == "" {
			return fmt.Errorf("sign-assertion: --audience is required")
		}
		if assertionSubject == "" {
			return fmt.Errorf("sign-assertion: --subject is required")
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("sign-assertion: failed to access enclave key: %w", err)
		}

		req := assertion.ClientAssertionRequest{
			Audience: assertionAudience,
			Subject:  assertionSubject,
			Nonce:    assertionNonce,
			Validity: assertionValidity,
			Format:   assertionFormat,
		}

		var resp *assertion.ClientAssertionResponse
		if assertionFormat == "webauthn" {
			resp, err = assertion.SynthesizeWebAuthnAssertion(req, priv)
		} else {
			resp, err = assertion.SignJWTAssertion(req, priv)
		}
		if err != nil {
			return err
		}

		if jsonOutput {
			data, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), resp.AssertionToken)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signAssertionCmd)
	signAssertionCmd.Flags().StringVar(&assertionAudience, "audience", "", "Target IdP token endpoint URL (required)")
	signAssertionCmd.Flags().StringVar(&assertionSubject, "subject", "", "Developer client ID or agent SPIFFE ID (required)")
	signAssertionCmd.Flags().StringVar(&assertionNonce, "nonce", "", "Anti-replay nonce/challenge")
	signAssertionCmd.Flags().DurationVar(&assertionValidity, "validity", 60*time.Second, "Assertion validity duration (max 5m)")
	signAssertionCmd.Flags().StringVar(&assertionFormat, "format", "jwt", "Assertion format: 'jwt' (RFC 7523) or 'webauthn'")
	signAssertionCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output detailed assertion metadata in JSON")
}
