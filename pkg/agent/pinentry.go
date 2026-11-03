package agent

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// RunPinentry handles GPG agent passphrase requests using the GPG Assuan Pinentry protocol
func RunPinentry(ls *locksmith.Locksmith) error {
	return RunPinentryWithIO(os.Stdin, os.Stdout, ls)
}

// RunPinentryWithIO handles GPG Assuan Pinentry requests with custom IO streams.
func RunPinentryWithIO(r io.Reader, w io.Writer, ls *locksmith.Locksmith) error {
	scanner := bufio.NewScanner(r)
	fmt.Fprintln(w, "OK Pinentry listener ready")

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "BYE") {
			fmt.Fprintln(w, "OK")
			break
		} else if strings.HasPrefix(line, "SETDESC ") {
			// We can capture the key description if needed
			fmt.Fprintln(w, "OK")
		} else if strings.HasPrefix(line, "GETPIN") {
			// Resolve GPG passphrase from Locksmith
			if ls != nil && ls.Options.AuditIdentity == "" {
				ls.Options.AuditIdentity = "gpg:pinentry"
			}
			passphraseBytes, err := ls.Get("gpg/passphrase")
			if err != nil {
				fmt.Fprintf(w, "ERR 111 General error: %v\n", err)
				continue
			}

			// Return the passphrase in the format: D <passphrase> followed by OK
			fmt.Fprintf(w, "D %s\n", string(passphraseBytes))
			fmt.Fprintln(w, "OK")

			// Clean memory
			for i := range passphraseBytes {
				passphraseBytes[i] = 0
			}
		} else {
			// Respond OK to any other commands (OPTION, SETPROMPT, etc.)
			fmt.Fprintln(w, "OK")
		}
	}
	return nil
}
