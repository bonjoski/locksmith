//go:build linux

package slice

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAdversarialLinuxHardwareSeals(t *testing.T) {
	secret := []byte("sealed-hardware-protected-token")
	sl, err := Create(secret)
	if err != nil {
		t.Fatalf("Create slice failed: %v", err)
	}
	defer sl.Close()

	// Verify all seals are active
	seals, err := GetSeals(sl.FD())
	if err != nil {
		t.Fatalf("GetSeals failed: %v", err)
	}

	requiredSeals := unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	if seals&requiredSeals != requiredSeals {
		t.Fatalf("Seals mismatch: got %x, expected %x", seals, requiredSeals)
	}

	// 1. Adversarial write attempt must fail with EPERM
	_, err = unix.Write(int(sl.FD()), []byte("tamper"))
	if err != unix.EPERM {
		t.Errorf("Expected EPERM on writing to sealed memfd, got %v", err)
	}

	// 2. Adversarial shrink/truncate attempt must fail with EPERM
	err = unix.Ftruncate(int(sl.FD()), 0)
	if err != unix.EPERM {
		t.Errorf("Expected EPERM on truncating sealed memfd, got %v", err)
	}

	// 3. Adversarial seal modification must fail with EPERM
	_, err = unix.FcntlInt(sl.FD(), unix.F_ADD_SEALS, 0)
	if err != unix.EPERM {
		t.Errorf("Expected EPERM on modifying sealed memfd seals, got %v", err)
	}
}
