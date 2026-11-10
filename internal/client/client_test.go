package client

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// wave-1 C3: apiAssertOK must exit 1 on HTTP >=400 (previously the client
// printed the error body and exited 0 — scripts saw success on failure).
// os.Exit is untestable in-process → subprocess pattern.
func TestApiAssertOK_Non4xxExitCode(t *testing.T) {
	if os.Getenv("KGATE_TEST_API_ASSERT") == "1" {
		apiAssertOK(500, []byte("ndmc: system failed"))
		return // must have exited
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestApiAssertOK_Non4xxExitCode")
	cmd.Env = append(os.Environ(), "KGATE_TEST_API_ASSERT=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("apiAssertOK(500, …) должен завершать процесс с ненулевым кодом, а не печатать и продолжать")
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("want exit status 1, got: %v", err)
	}
}

func TestApiAssertOK_OKPassthrough(t *testing.T) {
	b := apiAssertOK(200, []byte(`{"ok":true}`))
	if string(b) != `{"ok":true}` {
		t.Fatalf("body = %q", string(b))
	}
}
