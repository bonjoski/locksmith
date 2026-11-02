// Package ca provides local sovereign Certificate Authority (CA) management
// for the Bonjoski security ecosystem. This file implements atomic,
// double-buffered container export helpers for Docker, Envoy, and K3s.
package ca

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrSymlinkAttackDetected is returned when an export target is a symbolic link.
	ErrSymlinkAttackDetected = errors.New("security violation: symlink detected in export path")
	// ErrInvalidExportFormat is returned when an unsupported format is requested.
	ErrInvalidExportFormat = errors.New("unsupported export format: must be docker, envoy, or k3s")
)

// ExportFormat specifies the target configuration layout for container export.
type ExportFormat string

const (
	// FormatDocker exports certificates as ca.crt, tls.crt, and tls.key (or <name>.crt/<name>.key).
	FormatDocker ExportFormat = "docker"
	// FormatEnvoy exports certificates as ca.pem, cert.pem, and key.pem.
	FormatEnvoy ExportFormat = "envoy"
	// FormatK3s exports certificates according to Kubernetes Secret convention (ca.crt, tls.crt, tls.key).
	FormatK3s ExportFormat = "k3s"
)

// ExportOptions defines parameters for container certificate export.
type ExportOptions struct {
	OutDir  string
	Format  ExportFormat
	Name    string
	Profile *SVIDProfile
}

// ExportedFiles holds the resolved file basenames for a given format.
type ExportedFiles struct {
	CertName string
	KeyName  string
	CAName   string
}

// ResolveFilenames determines output file names based on format and workload name.
func ResolveFilenames(format ExportFormat, name string) (*ExportedFiles, error) {
	cleanFormat := ExportFormat(strings.ToLower(string(format)))
	if cleanFormat == "" {
		cleanFormat = FormatDocker
	}

	switch cleanFormat {
	case FormatDocker:
		certName := "tls.crt"
		keyName := "tls.key"
		if name != "" {
			certName = fmt.Sprintf("%s.crt", name)
			keyName = fmt.Sprintf("%s.key", name)
		}
		return &ExportedFiles{
			CertName: certName,
			KeyName:  keyName,
			CAName:   "ca.crt",
		}, nil
	case FormatEnvoy:
		return &ExportedFiles{
			CertName: "cert.pem",
			KeyName:  "key.pem",
			CAName:   "ca.pem",
		}, nil
	case FormatK3s:
		return &ExportedFiles{
			CertName: "tls.crt",
			KeyName:  "tls.key",
			CAName:   "ca.crt",
		}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidExportFormat, format)
	}
}

// ZeroBytes explicitly clears memory buffers to prevent private key residue.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func checkSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: path %s is a symlink", ErrSymlinkAttackDetected, path)
	}
	return nil
}

func prepareExportDir(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create export directory %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed inspecting export directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: export directory %s is a symlink", ErrSymlinkAttackDetected, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("export path %s exists and is not a directory", dir)
	}
	if info.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("failed enforcing 0700 permissions on %s: %w", dir, err)
		}
	}
	return nil
}

// WriteAtomicFile writes data to a temporary file in dir and atomically renames it to filename.
func WriteAtomicFile(dir, filename string, data []byte, perm os.FileMode) error {
	targetPath := filepath.Join(dir, filename)
	if err := checkSymlink(targetPath); err != nil {
		return err
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%x", filename, nonce))

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("failed to create temporary file %s: %w", tmpPath, err)
	}

	var writeErr error
	if _, err := f.Write(data); err != nil {
		writeErr = fmt.Errorf("failed writing to %s: %w", tmpPath, err)
	} else if err := f.Sync(); err != nil {
		writeErr = fmt.Errorf("failed syncing %s: %w", tmpPath, err)
	}

	if closeErr := f.Close(); closeErr != nil && writeErr == nil {
		writeErr = fmt.Errorf("failed closing %s: %w", tmpPath, closeErr)
	}

	if writeErr != nil {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !os.IsNotExist(rmErr) {
			writeErr = fmt.Errorf("%w (cleanup failed: %v)", writeErr, rmErr)
		}
		return writeErr
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("failed atomic rename %s -> %s: %w (cleanup failed: %v)", tmpPath, targetPath, err, rmErr)
		}
		return fmt.Errorf("failed atomic rename %s -> %s: %w", tmpPath, targetPath, err)
	}

	return nil
}

// ExportContainerCerts generates an SVID bundle and exports it atomically into opts.OutDir.
func (c *CA) ExportContainerCerts(opts *ExportOptions) error {
	if opts == nil || opts.OutDir == "" {
		return errors.New("out-dir is required for container export")
	}

	files, err := ResolveFilenames(opts.Format, opts.Name)
	if err != nil {
		return err
	}

	if err := prepareExportDir(opts.OutDir); err != nil {
		return err
	}

	bundle, err := c.IssueDualSVID(opts.Profile)
	if err != nil {
		return fmt.Errorf("failed to issue SVID for container export: %w", err)
	}

	// Zeroize private key in memory once written to disk
	defer ZeroBytes(bundle.KeyPEM)

	// Write Certificate (0644)
	if err := WriteAtomicFile(opts.OutDir, files.CertName, bundle.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed writing certificate: %w", err)
	}

	// Write Private Key (0600 - strictly locked down)
	if err := WriteAtomicFile(opts.OutDir, files.KeyName, bundle.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed writing private key: %w", err)
	}

	// Write Root CA Certificate (0644)
	caCertPEM := c.DualCertPEM
	if len(caCertPEM) == 0 {
		caCertPEM = c.CertPEM
	}
	if err := WriteAtomicFile(opts.OutDir, files.CAName, caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed writing CA certificate: %w", err)
	}

	return nil
}

// AutoRotateLoop periodically exports renewed certificates at half the validity TTL.
func (c *CA) AutoRotateLoop(opts *ExportOptions, stopCh <-chan struct{}, onRotate func()) error {
	ttl := DefaultSVIDTTL
	if opts.Profile != nil && opts.Profile.TTL > 0 {
		ttl = opts.Profile.TTL
	}

	interval := ttl / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return nil
		case <-ticker.C:
			if err := c.ExportContainerCerts(opts); err != nil {
				return fmt.Errorf("auto-rotation failed: %w", err)
			}
			if onRotate != nil {
				onRotate()
			}
		}
	}
}
