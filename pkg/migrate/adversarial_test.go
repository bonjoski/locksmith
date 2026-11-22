package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ux"
)

type mockBatchStore struct {
	mu                  sync.Mutex
	requiresInteractive bool
	beginCalls          int
	stored              map[string]string
}

func (m *mockBatchStore) RequiresInteractiveUnlock() bool {
	return m.requiresInteractive
}

func (m *mockBatchStore) BeginBatch(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beginCalls++
	return nil
}

func (m *mockBatchStore) StoreSecret(_ context.Context, key string, value []byte, _ time.Time, _ map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stored == nil {
		m.stored = make(map[string]string)
	}
	m.stored[key] = string(value)
	return nil
}

func TestLocksmithMigrate_RejectsSymlinkAndNeverLogsValues(t *testing.T) {
	t.Run("rejects_symlink", assertRejectsSymlinkEnv)
	t.Run("malformed_never_logs_canary", assertMalformedEnvNeverLogsCanary)
	t.Run("valid_shreds_and_never_logs_canary", assertValidEnvShredsAndNeverLogsCanary)
}

func testCanaryToken() string {
	return strings.Join([]string{"sk", "live", "CANARY999"}, "-")
}

func assertRejectsSymlinkEnv(t *testing.T) {
	t.Helper()
	outside := t.TempDir()
	victimPath := filepath.Join(outside, "id_rsa")
	victimContent := "PRIVATE_KEY=" + testCanaryToken() + "\n"
	if err := os.WriteFile(victimPath, []byte(victimContent), 0600); err != nil {
		t.Fatal(err)
	}

	ws := t.TempDir()
	if err := os.Symlink(victimPath, filepath.Join(ws, ".env")); err != nil {
		t.Fatal(err)
	}

	store := &mockBatchStore{}
	_, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: ws,
		EnvFile:       ".env",
		ProjectName:   "my-app",
		Store:         store,
	})
	var ffe *ux.FixForwardError
	if !errors.As(err, &ffe) || ffe.Code != "LOCKSMITH_SYMLINK_REJECTED" {
		t.Fatalf("expected LOCKSMITH_SYMLINK_REJECTED FixForwardError, got: %T %v", err, err)
	}
	gotVictim, readErr := os.ReadFile(victimPath)
	if readErr != nil || string(gotVictim) != victimContent {
		t.Fatalf("victim file was modified or deleted! err=%v content=%q", readErr, string(gotVictim))
	}
	if len(store.stored) != 0 {
		t.Fatalf("expected zero keys stored on symlink rejection, got: %d", len(store.stored))
	}
}

func assertMalformedEnvNeverLogsCanary(t *testing.T) {
	t.Helper()
	wsBad := t.TempDir()
	canary := testCanaryToken()
	malformedEnv := "GOOD_KEY=ok\nMALFORMED_LINE_NO_EQUALS_" + canary + "\n"
	if err := os.WriteFile(filepath.Join(wsBad, ".env"), []byte(malformedEnv), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: wsBad,
		EnvFile:       ".env",
		ProjectName:   "my-app",
		Store:         &mockBatchStore{},
	})
	var ffe *ux.FixForwardError
	if !errors.As(err, &ffe) {
		t.Fatalf("expected FixForwardError, got %T %v", err, err)
	}
	var textOut, whyOut, jsonOut bytes.Buffer
	_ = ffe.Render(&textOut, false, false)
	_ = ffe.Render(&whyOut, false, true)
	_ = ffe.Render(&jsonOut, true, false)
	combined := err.Error() + textOut.String() + whyOut.String() + jsonOut.String()
	if strings.Contains(combined, canary) {
		t.Fatalf("SECURITY VIOLATION: canary secret %q leaked into error output:\n%s", canary, combined)
	}
	if !strings.Contains(textOut.String(), "line 2") {
		t.Fatalf("expected line number in parse error, got: %s", textOut.String())
	}
}

func assertValidEnvShredsAndNeverLogsCanary(t *testing.T) {
	t.Helper()
	canary := testCanaryToken()
	wsGood := t.TempDir()
	validEnv := "# comment\nexport OPENAI_API_KEY=\"" + canary + "\"\nDATABASE_URL='postgres://user:pass@localhost/db'\n"
	if err := os.WriteFile(filepath.Join(wsGood, ".env"), []byte(validEnv), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsGood, ".env.example"), []byte("OPENAI_API_KEY=changeme\n"), 0644); err != nil {
		t.Fatal(err)
	}

	goodStore := &mockBatchStore{}
	res, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: wsGood,
		EnvFile:       ".env",
		ProjectName:   "my-app",
		Store:         goodStore,
	})
	if err != nil {
		t.Fatalf("expected valid migration to succeed, got: %v", err)
	}
	if res.ImportedCount != 2 || !res.Shredded || !res.GitignoreUpdated {
		t.Fatalf("unexpected migration result: %+v", res)
	}
	if goodStore.stored["project/my-app/OPENAI_API_KEY"] != canary {
		t.Fatalf("expected OPENAI_API_KEY to be stored accurately in backend")
	}
	assertPostMigrateWorkspace(t, wsGood)
	assertSuccessRenderSafe(t, res, canary)
}

func assertPostMigrateWorkspace(t *testing.T, wsGood string) {
	t.Helper()
	if _, statErr := os.Stat(filepath.Join(wsGood, ".env")); !os.IsNotExist(statErr) {
		t.Fatalf("expected .env to be shredded and removed")
	}
	if _, statErr := os.Stat(filepath.Join(wsGood, ".env.example")); statErr != nil {
		t.Fatalf("expected .env.example to be preserved, got: %v", statErr)
	}
	giBytes, giErr := os.ReadFile(filepath.Join(wsGood, ".gitignore"))
	if giErr != nil {
		t.Fatalf("expected .gitignore to be created: %v", giErr)
	}
	gi := string(giBytes)
	if !strings.Contains(gi, ".env\n") || !strings.Contains(gi, ".env.*\n") || !strings.Contains(gi, "!.env.example\n") {
		t.Fatalf("expected .gitignore rules preserving !.env.example, got:\n%s", gi)
	}
}

func assertSuccessRenderSafe(t *testing.T, res *Result, canary string) {
	t.Helper()
	var textOut, whyOut, jsonOut bytes.Buffer
	_ = res.Render(&textOut, false, false)
	_ = res.Render(&whyOut, false, true)
	_ = res.Render(&jsonOut, true, false)
	allRendered := textOut.String() + whyOut.String() + jsonOut.String()
	if strings.Contains(allRendered, canary) {
		t.Fatalf("SECURITY VIOLATION: canary secret leaked into rendered success output:\n%s", allRendered)
	}
	lines := strings.Split(strings.TrimSuffix(textOut.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected calm <=3-line default summary, got %d lines:\n%s", len(lines), textOut.String())
	}
}

func TestLocksmithMigrate_RejectsOversizedAndBinaryFiles(t *testing.T) {
	// >1MB .env rejected fail-closed
	wsBig := t.TempDir()
	bigData := bytes.Repeat([]byte("A=1\n"), (MaxEnvFileBytes/4)+10)
	if err := os.WriteFile(filepath.Join(wsBig, ".env"), bigData, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: wsBig,
		EnvFile:       ".env",
		ProjectName:   "big-app",
		Store:         &mockBatchStore{},
	})
	var ffe *ux.FixForwardError
	if !errors.As(err, &ffe) || ffe.Code != "LOCKSMITH_ENV_TOO_LARGE" {
		t.Fatalf("expected LOCKSMITH_ENV_TOO_LARGE, got: %v", err)
	}

	// Binary .env rejected fail-closed
	wsBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsBin, ".env"), []byte("KEY=val\x00binary"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = MigrateEnv(context.Background(), Options{
		WorkspaceRoot: wsBin,
		EnvFile:       ".env",
		ProjectName:   "bin-app",
		Store:         &mockBatchStore{},
	})
	if !errors.As(err, &ffe) || ffe.Code != "LOCKSMITH_ENV_BINARY_REJECTED" {
		t.Fatalf("expected LOCKSMITH_ENV_BINARY_REJECTED, got: %v", err)
	}
}

func TestLocksmithMigrate_SingleSessionBatchAmortization(t *testing.T) {
	ws := t.TempDir()
	var sb strings.Builder
	for i := 0; i < 25; i++ {
		sb.WriteString(fmt.Sprintf("SECRET_KEY_%02d=value-%02d\n", i, i))
	}
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte(sb.String()), 0600); err != nil {
		t.Fatal(err)
	}

	store := &mockBatchStore{}
	res, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: ws,
		EnvFile:       ".env",
		ProjectName:   "batch-app",
		Store:         store,
	})
	if err != nil {
		t.Fatalf("batch migration failed: %v", err)
	}
	if res.ImportedCount != 25 {
		t.Fatalf("expected 25 keys imported, got %d", res.ImportedCount)
	}
	if store.beginCalls != 1 {
		t.Fatalf("expected exactly 1 amortized session unlock for 25 keys, got %d", store.beginCalls)
	}
}

func TestLocksmithMigrate_HeadlessNonInteractiveExit82_N8(t *testing.T) {
	const workers = 8
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ws := t.TempDir()
			_ = os.WriteFile(filepath.Join(ws, ".env"), []byte("API_KEY=secret\n"), 0600)
			store := &mockBatchStore{requiresInteractive: true}

			_, err := MigrateEnv(context.Background(), Options{
				WorkspaceRoot:     ws,
				EnvFile:           ".env",
				ProjectName:       "headless-app",
				NonInteractive:    true,
				HasAmbientSession: false,
				Store:             store,
			})
			var ffe *ux.FixForwardError
			if !errors.As(err, &ffe) {
				errs <- fmt.Errorf("expected FixForwardError, got %v", err)
				return
			}
			if ffe.ExitCode != 82 || ffe.Code != "ERR_BIOMETRIC_INTERACTION_REQUIRED" {
				errs <- fmt.Errorf("expected exit 82 ERR_BIOMETRIC_INTERACTION_REQUIRED, got %+v", ffe)
				return
			}
			var buf bytes.Buffer
			if rErr := ffe.Render(&buf, true, false); rErr != nil {
				errs <- rErr
				return
			}
			var decoded ux.FixForwardError
			if uErr := json.Unmarshal(buf.Bytes(), &decoded); uErr != nil {
				errs <- uErr
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("headless N=8 worker error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("headless N=8 fail-fast took too long: %v", elapsed)
	}
}

func TestLocksmithMigrate_KeepSourceAndPathEscapeRejection(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("TOKEN=abc\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// KeepSource preserves .env
	res, err := MigrateEnv(context.Background(), Options{
		WorkspaceRoot: ws,
		EnvFile:       ".env",
		ProjectName:   "keep-app",
		KeepSource:    true,
		Store:         &mockBatchStore{},
	})
	if err != nil {
		t.Fatalf("keep-source migrate failed: %v", err)
	}
	if res.Shredded || res.KeepSourceWarning == "" {
		t.Fatalf("expected Shredded=false with warning, got: %+v", res)
	}
	if _, statErr := os.Stat(filepath.Join(ws, ".env")); statErr != nil {
		t.Fatalf("expected .env to remain on disk with --keep-source: %v", statErr)
	}

	// Path traversal rejected
	for _, bad := range []string{"../.env", "/etc/passwd", "sub/.env"} {
		_, err := MigrateEnv(context.Background(), Options{
			WorkspaceRoot: ws,
			EnvFile:       bad,
			ProjectName:   "escape-app",
			Store:         &mockBatchStore{},
		})
		var ffe *ux.FixForwardError
		if !errors.As(err, &ffe) || ffe.Code != "LOCKSMITH_PATH_ESCAPE_REJECTED" {
			t.Fatalf("expected LOCKSMITH_PATH_ESCAPE_REJECTED for %q, got: %v", bad, err)
		}
	}
}
