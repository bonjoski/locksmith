package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAuditEventNormalization(t *testing.T) {
	ev := Event{
		SecretName: "test/secret",
	}.Normalize()

	if ev.ID == "" {
		t.Errorf("expected auto-generated ID, got empty")
	}
	if ev.TimestampMS <= 0 {
		t.Errorf("expected positive TimestampMS, got %d", ev.TimestampMS)
	}
	if ev.ClientPID <= 0 {
		t.Errorf("expected positive ClientPID, got %d", ev.ClientPID)
	}
	if ev.BinaryPath == "" {
		t.Errorf("expected non-empty BinaryPath")
	}
	if ev.BinaryHash == "" {
		t.Errorf("expected non-empty BinaryHash")
	}
	if ev.Identity == "" {
		t.Errorf("expected non-empty Identity")
	}
	if ev.Outcome != OutcomeGranted {
		t.Errorf("expected default OutcomeGranted, got %s", ev.Outcome)
	}
}

func readEventsFromDisk(t *testing.T, path string) []Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var readEvents []Event
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var parsed Event
		if err := json.Unmarshal(line, &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON line: %v", err)
		}
		readEvents = append(readEvents, parsed)
	}
	return readEvents
}

func TestWriteAndReadAuditEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	events := []Event{
		{
			SecretName: "git/github.com/bonjoski",
			Identity:   "git-credential",
			Outcome:    OutcomeGranted,
			Reason:     "Git credential query",
		},
		{
			SecretName: "gpg/passphrase",
			Identity:   "gpg:pinentry",
			Outcome:    OutcomeGranted,
			Reason:     "GPG signing passphrase request",
		},
		{
			SecretName: "unauthorized/key",
			Identity:   "cli:locksmith",
			Outcome:    OutcomeDenied,
			Reason:     "Denied by policy",
		},
		{
			SecretName: "ephemeral/lease-1",
			Identity:   "spiffe://aegisbox.internal/agent/sandbox",
			Outcome:    OutcomeRevoked,
			Reason:     "Lease TTL expired",
		},
	}

	for _, ev := range events {
		if err := WriteEvent(logPath, ev); err != nil {
			t.Fatalf("WriteEvent failed: %v", err)
		}
	}

	readEvents := readEventsFromDisk(t, logPath)
	if len(readEvents) != 4 {
		t.Fatalf("expected 4 events, got %d", len(readEvents))
	}

	if readEvents[0].SecretName != "git/github.com/bonjoski" || readEvents[0].Outcome != OutcomeGranted {
		t.Errorf("unexpected event 0: %+v", readEvents[0])
	}
	if readEvents[1].SecretName != "gpg/passphrase" || readEvents[1].Identity != "gpg:pinentry" {
		t.Errorf("unexpected event 1: %+v", readEvents[1])
	}
	if readEvents[2].Outcome != OutcomeDenied || readEvents[2].Reason != "Denied by policy" {
		t.Errorf("unexpected event 2: %+v", readEvents[2])
	}
	if readEvents[3].Outcome != OutcomeRevoked || readEvents[3].Reason != "Lease TTL expired" {
		t.Errorf("unexpected event 3: %+v", readEvents[3])
	}
}

func TestConcurrentAuditWriting(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "concurrent_audit.jsonl")

	var wg sync.WaitGroup
	workers := 10
	eventsPerWorker := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerWorker; j++ {
				ev := Event{
					SecretName: "test/secret",
					Identity:   "worker",
					Outcome:    OutcomeGranted,
					ClientPID:  1000 + workerID,
				}
				if err := WriteEvent(logPath, ev); err != nil {
					t.Errorf("worker %d write failed: %v", workerID, err)
				}
			}
		}()
	}

	wg.Wait()

	// Read and verify all 200 events are valid uncorrupted JSON lines
	file, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		var parsed Event
		if err := json.Unmarshal(line, &parsed); err != nil {
			t.Fatalf("corrupted JSON encountered at line %d: %v", count+1, err)
		}
		count++
	}

	expected := workers * eventsPerWorker
	if count != expected {
		t.Fatalf("expected %d lines, got %d", expected, count)
	}
}
