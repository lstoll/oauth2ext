package tpmsecrets

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/tokencache"
)

func TestE2E(t *testing.T) {
	if runtime.GOOS != "windows" {
		swtpmPath, err := exec.LookPath("swtpm")
		if err != nil {
			t.Skip("swtpm not found, skipping E2E test")
		}

		// Create temp dir for state
		tmpDir := t.TempDir()
		tpmStateDir := filepath.Join(tmpDir, "tpm-state")
		if err := os.Mkdir(tpmStateDir, 0700); err != nil {
			t.Fatal(err)
		}

		// Pick a random port
		// This is slightly racey but fine for local tests
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		addr := fmt.Sprintf("127.0.0.1:%d", port)

		// Start swtpm
		// swtpm socket --tpm2 --server type=tcp,port=<port> --ctrl type=tcp,port=<ctrl-port> --tpmstate dir=<dir> --flags not-need-init,startup-clear
		// We use --flags startup-clear so we don't need to send TPM2_Startup manually (though we could).
		cmd := exec.Command(swtpmPath, "socket",
			"--tpm2",
			"--server", fmt.Sprintf("type=tcp,port=%d", port),
			"--ctrl", fmt.Sprintf("type=tcp,port=%d", port+1), // Just need a ctrl port, unused
			"--tpmstate", fmt.Sprintf("dir=%s", tpmStateDir),
			"--flags", "not-need-init,startup-clear",
		)

		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		// Wait for socket
		if !waitForPort(addr, 5*time.Second) {
			t.Fatalf("swtpm did not come up on %s", addr)
		}

		// Set env
		t.Setenv("TPM_TEST_SOCKET", addr)
	} else {
		// On Windows, try to use system TPM
		tpm, err := openTPM()
		if err != nil {
			t.Skipf("System TPM not available: %v", err)
		}
		closeTPM(tpm)
	}

	tmpDir := t.TempDir()

	// Run Tests
	t.Run("Store", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "store")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		platformsecrets.TestStore(t, &TPMCredentialCache{Dir: dir})
	})

	t.Run("Cache", func(t *testing.T) {
		cacheDir := filepath.Join(tmpDir, "cache")
		if err := os.Mkdir(cacheDir, 0700); err != nil {
			t.Fatal(err)
		}

		c := &TPMCredentialCache{Dir: cacheDir}

		if !c.Available() {
			t.Fatal("Cache not available")
		}

		token := &oauth2.Token{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
		}

		// Set
		if err := c.Set("https://issuer.com", "client-id", &tokencache.Credential{Token: token}); err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		// Get
		got, err := c.Get("https://issuer.com", "client-id")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if got == nil {
			t.Fatal("Get returned nil")
		}
		if got.Token.AccessToken != "test-access-token" {
			t.Errorf("Got token %q, want %q", got.Token.AccessToken, "test-access-token")
		}

		// Verify persistence by recreating cache
		c2 := &TPMCredentialCache{Dir: cacheDir}
		got2, err := c2.Get("https://issuer.com", "client-id")
		if err != nil {
			t.Fatalf("Get2 failed: %v", err)
		}
		if got2 == nil {
			t.Fatal("Get2 returned nil")
		}
		if got2.Token.AccessToken != "test-access-token" {
			t.Errorf("Got2 token %q, want %q", got2.Token.AccessToken, "test-access-token")
		}
	})
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
