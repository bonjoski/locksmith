package agent

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// RunPinentry handles GPG agent passphrase requests using the GPG Assuan Pinentry protocol
func RunPinentry(ls *locksmith.Locksmith) error {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("OK Pinentry listener ready")

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "BYE") {
			fmt.Println("OK")
			break
		} else if strings.HasPrefix(line, "SETDESC ") {
			// We can capture the key description if needed
			fmt.Println("OK")
		} else if strings.HasPrefix(line, "GETPIN") {
			// Resolve GPG passphrase from Locksmith
			passphraseBytes, err := ls.Get("gpg/passphrase")
			if err != nil {
				fmt.Fprintf(os.Stdout, "ERR 111 General error: %v\n", err)
				continue
			}

			// Return the passphrase in the format: D <passphrase> followed by OK
			fmt.Fprintf(os.Stdout, "D %s\n", string(passphraseBytes))
			fmt.Println("OK")

			// Clean memory
			for i := range passphraseBytes {
				passphraseBytes[i] = 0
			}
		} else {
			// Respond OK to any other commands (OPTION, SETPROMPT, etc.)
			fmt.Println("OK")
		}
	}
	return nil
}
