package agent

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
)

// AssuanPercentEncode escapes %, CR, LF, and NUL per the GnuPG Assuan line protocol
// so untrusted prompt or description text cannot inject arbitrary Assuan commands.
func AssuanPercentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			b.WriteString("%25")
		case '\r':
			b.WriteString("%0D")
		case '\n':
			b.WriteString("%0A")
		case 0:
			b.WriteString("%00")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// FormatAssuanSetDesc constructs a sanitized Assuan SETDESC command line.
func FormatAssuanSetDesc(desc string) string {
	return "SETDESC " + AssuanPercentEncode(desc)
}

// FormatAssuanSetPrompt constructs a sanitized Assuan SETPROMPT command line.
func FormatAssuanSetPrompt(prompt string) string {
	return "SETPROMPT " + AssuanPercentEncode(prompt)
}

func encodeAssuanDataBytes(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for _, c := range raw {
		switch c {
		case '%':
			out = append(out, '%', '2', '5')
		case '\r':
			out = append(out, '%', '0', 'D')
		case '\n':
			out = append(out, '%', '0', 'A')
		case 0:
			out = append(out, '%', '0', '0')
		default:
			out = append(out, c)
		}
	}
	return out
}

// RunPinentry handles GPG agent passphrase requests using the GPG Assuan Pinentry protocol
func RunPinentry(ls *locksmith.Locksmith) error {
	return RunPinentryWithIO(os.Stdin, os.Stdout, ls)
}

// RunPinentryWithIO handles GPG Assuan Pinentry requests with custom IO streams.
func RunPinentryWithIO(r io.Reader, w io.Writer, ls *locksmith.Locksmith) error {
	scanner := bufio.NewScanner(r)
	if _, err := fmt.Fprintln(w, "OK Pinentry listener ready"); err != nil {
		return err
	}

	var safeDesc, safePrompt string

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "BYE"):
			_, _ = fmt.Fprintln(w, "OK")
			return scanner.Err()
		case strings.HasPrefix(line, "SETDESC ") || line == "SETDESC":
			safeDesc = AssuanPercentEncode(strings.TrimPrefix(line, "SETDESC "))
			_ = safeDesc
			_, _ = fmt.Fprintln(w, "OK")
		case strings.HasPrefix(line, "SETPROMPT ") || line == "SETPROMPT":
			safePrompt = AssuanPercentEncode(strings.TrimPrefix(line, "SETPROMPT "))
			_ = safePrompt
			_, _ = fmt.Fprintln(w, "OK")
		case strings.HasPrefix(line, "GETPIN"):
			if ls == nil {
				_, _ = fmt.Fprintln(w, "ERR 111 General error: locksmith instance is nil")
				continue
			}
			opts := ls.Options
			if opts.AuditIdentity == "" {
				opts.AuditIdentity = "gpg:pinentry"
			}
			passphraseBytes, err := ls.GetWithOptions("gpg/passphrase", opts)
			if err != nil {
				_, _ = fmt.Fprintf(w, "ERR 111 General error: %s\n", AssuanPercentEncode(err.Error()))
				continue
			}

			escaped := encodeAssuanDataBytes(passphraseBytes)
			slice.ExplicitBzero(passphraseBytes)

			lineBuf := make([]byte, 0, len(escaped)+3)
			lineBuf = append(lineBuf, 'D', ' ')
			lineBuf = append(lineBuf, escaped...)
			lineBuf = append(lineBuf, '\n')
			slice.ExplicitBzero(escaped)

			_, _ = w.Write(lineBuf)
			slice.ExplicitBzero(lineBuf)
			_, _ = fmt.Fprintln(w, "OK")
		default:
			_, _ = fmt.Fprintln(w, "OK")
		}
	}
	return scanner.Err()
}
