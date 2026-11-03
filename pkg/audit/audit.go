package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Outcome represents the authorization or lifecycle outcome of a secret access.
type Outcome string

const (
	OutcomeGranted Outcome = "GRANTED"
	OutcomeDenied  Outcome = "DENIED"
	OutcomeRevoked Outcome = "REVOKED"
)

// Event matches the Cockpit AuditEvent schema for zero-trust tracking.
type Event struct {
	ID          string  `json:"id"`
	TimestampMS int64   `json:"timestamp_ms"`
	SecretName  string  `json:"secret_name"`
	ClientPID   int     `json:"client_pid"`
	BinaryPath  string  `json:"binary_path"`
	BinaryHash  string  `json:"binary_hash"`
	Identity    string  `json:"identity"`
	Outcome     Outcome `json:"outcome"`
	Reason      string  `json:"reason,omitempty"`
}

var (
	procMu       sync.Mutex
	selfHashOnce sync.Once
	selfHash     string
	selfExePath  string
)

// DefaultAuditPath returns the path to the persistent audit log file.
func DefaultAuditPath() string {
	if p := os.Getenv("LOCKSMITH_AUDIT_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "audit.jsonl")
	}
	return filepath.Join(os.TempDir(), "locksmith_audit.jsonl")
}

// HashFile computes the sha256 checksum formatted as sha256:<hex>.
func HashFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty file path")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func getSelfBinaryInfo() (path string, hash string) {
	selfHashOnce.Do(func() {
		exe, err := os.Executable()
		if err == nil {
			selfExePath = exe
			if h, err := HashFile(exe); err == nil {
				selfHash = h
			}
		}
	})
	return selfExePath, selfHash
}

func defaultIdentity(binaryPath string) string {
	if id := os.Getenv("LOCKSMITH_AUDIT_IDENTITY"); id != "" {
		return id
	}
	base := filepath.Base(binaryPath)
	switch {
	case strings.Contains(base, "git-credential"):
		return "git-credential"
	case strings.Contains(base, "pinentry"):
		return "gpg:pinentry"
	case strings.Contains(base, "summon"):
		return "summon"
	case strings.Contains(base, "locksmith-cockpit"):
		return "cockpit"
	case base != "" && base != ".":
		return "cli:" + strings.TrimSuffix(base, filepath.Ext(base))
	default:
		return fmt.Sprintf("user:%d", os.Getuid())
	}
}

// Normalize populates any unset fields with system context.
func (e Event) Normalize() Event {
	if e.TimestampMS <= 0 {
		e.TimestampMS = time.Now().UnixMilli()
	}

	if e.ID == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		e.ID = fmt.Sprintf("aud-%d-%s", e.TimestampMS, hex.EncodeToString(b[:]))
	}

	if e.ClientPID <= 0 {
		e.ClientPID = os.Getpid()
	}

	exePath, exeHash := getSelfBinaryInfo()
	if e.BinaryPath == "" {
		e.BinaryPath = exePath
	}
	if e.BinaryHash == "" {
		if e.BinaryPath == exePath {
			e.BinaryHash = exeHash
		} else if e.BinaryPath != "" {
			if h, err := HashFile(e.BinaryPath); err == nil {
				e.BinaryHash = h
			}
		}
	}

	if e.Identity == "" {
		e.Identity = defaultIdentity(e.BinaryPath)
	}

	if e.Outcome == "" {
		e.Outcome = OutcomeGranted
	}

	return e
}

// WriteEvent writes an event directly to a designated log path with cross-process locking.
func WriteEvent(path string, ev Event) error {
	ev = ev.Normalize()

	procMu.Lock()
	defer procMu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("audit: failed to create directory %q: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("audit: failed to open log file %q: %w", path, err)
	}
	defer f.Close()

	if err := lockFile(f); err != nil {
		return fmt.Errorf("audit: failed to acquire file lock: %w", err)
	}
	defer func() {
		_ = unlockFile(f)
	}()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("audit: failed to seek to end of %q: %w", path, err)
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: failed to marshal event: %w", err)
	}

	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("audit: failed to append event: %w", err)
	}

	return nil
}

// Log writes an event to the default persistent audit log path.
func Log(ev Event) error {
	return WriteEvent(DefaultAuditPath(), ev)
}

// LogGranted logs an authorized secret access.
func LogGranted(secretName, identity, reason string) error {
	return Log(Event{
		SecretName: secretName,
		Identity:   identity,
		Outcome:    OutcomeGranted,
		Reason:     reason,
	})
}

// LogDenied logs a rejected or failed secret access attempt.
func LogDenied(secretName, identity, reason string) error {
	return Log(Event{
		SecretName: secretName,
		Identity:   identity,
		Outcome:    OutcomeDenied,
		Reason:     reason,
	})
}

// LogRevoked logs a lease expiration or secret deletion event.
func LogRevoked(secretName, identity, reason string) error {
	return Log(Event{
		SecretName: secretName,
		Identity:   identity,
		Outcome:    OutcomeRevoked,
		Reason:     reason,
	})
}
