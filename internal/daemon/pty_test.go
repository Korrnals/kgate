package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestPtyHelperProcess — child-процесс для тестов PTY-читалки (pattern
// client_test.go: ре-экзек тестового бинаря под env-гейтом). Вывод идёт
// через pty-slave посимвольно-построчными Write — читатель обязан корректно
// дренировать частичные чтения и дожить до EIO/EOF мастера.
func TestPtyHelperProcess(t *testing.T) {
	if os.Getenv("KGATE_TEST_PTY_HELPER") != "1" {
		return
	}
	switch os.Getenv("KGATE_TEST_PTY_MODE") {
	case "large":
		// 3000 строк × ~100 байт ≈ 300 KB — на порядок больше pipe-буфера:
		// клипующая читалка или потерянный хвост видны сразу.
		for i := 0; i < 3000; i++ {
			fmt.Fprintf(os.Stdout, "cfg line %04d %s\x1b[K\r\n", i, strings.Repeat("p", 80))
		}
		fmt.Fprint(os.Stdout, "KGATE_PTY_TAIL_MARKER\r\n")
	case "ansi":
		fmt.Fprint(os.Stdout, "\x1b[Kip hotspot\r\n    \x1b[Khost aa:bb:cc:dd:ee:ff policy VPN\x1b[K\r\n\x1b[2J")
	case "fail":
		fmt.Fprint(os.Stdout, "partial stdout before death\r\n")
		fmt.Fprint(os.Stderr, "boom on stderr\r\n")
		os.Exit(3)
	case "hang":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func ptyHelper(t *testing.T, mode string, timeout time.Duration) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestPtyHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		"KGATE_TEST_PTY_HELPER=1",
		"KGATE_TEST_PTY_MODE="+mode,
	)
	return ptyRun(cmd, timeout)
}

// TestPtyRunLargeOutputNoClip — ядро регрессии kgate-002: полный дренаж
// большого вывода через PTY (300 KB >> pipe-буфер 64 KB), хвост не теряется,
// ANSI/CR вычищены, длина побайтно совпадает с ожидаемой.
func TestPtyRunLargeOutputNoClip(t *testing.T) {
	out, err := ptyHelper(t, "large", 30*time.Second)
	if err != nil {
		t.Fatalf("ptyRun: %v", err)
	}
	if !strings.Contains(out, "cfg line 0000") {
		t.Errorf("голова вывода потеряна")
	}
	// хвост — единственное место, куда бьёт клип non-tty ndmc (kgate-001):
	if !strings.Contains(out, "KGATE_PTY_TAIL_MARKER") {
		t.Errorf("хвост вывода потерян — читалка клипует")
	}
	if strings.Contains(out, "\x1b[K") || strings.Contains(out, "\r") {
		t.Errorf("ANSI/CR мусор не вычищен")
	}
	// побайтная сверка: 3000 строк + хвост-маркер (после чистки — \n)
	var want strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&want, "cfg line %04d %s\n", i, strings.Repeat("p", 80))
	}
	want.WriteString("KGATE_PTY_TAIL_MARKER\n")
	if out != want.String() {
		t.Fatalf("вывод ≠ ожиданию: got %d bytes, want %d", len(out), want.Len())
	}
}

// TestPtyRunCapturesTailMarker — маркер в ПОСЛЕДНЕЙ строке выживает (контракт
// «парсеры видят хвост running-config»: привязки ip hotspot растут к концу
// конфига).
func TestPtyRunCapturesTailMarker(t *testing.T) {
	out, err := ptyHelper(t, "large", 30*time.Second)
	if err != nil {
		t.Fatalf("ptyRun: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	last := lines[len(lines)-1]
	if last != "KGATE_PTY_TAIL_MARKER" {
		t.Errorf("последняя строка = %q, want KGATE_PTY_TAIL_MARKER (хвост потерян)", last)
	}
}

// TestPtyRunCleansANSIAndCR — PTY-рендер (\x1b[K, \r, CSI) вычищается до
// возврата: парсеры демона работают по чистым строкам (truth table 08.11).
func TestPtyRunCleansANSIAndCR(t *testing.T) {
	out, err := ptyHelper(t, "ansi", 30*time.Second)
	if err != nil {
		t.Fatalf("ptyRun: %v", err)
	}
	want := "ip hotspot\n    host aa:bb:cc:dd:ee:ff policy VPN"
	if strings.TrimSpace(out) != want {
		t.Errorf("после чистки = %q, want %q", strings.TrimSpace(out), want)
	}
}

// TestPtyRunExitFailureSurface — не-нулевой exit: (out, err) пара сохраняется,
// err несёт "exit status 3" — вызывающий склеит sh()-совместимый "ERR(...)".
func TestPtyRunExitFailureSurface(t *testing.T) {
	out, err := ptyHelper(t, "fail", 30*time.Second)
	if err == nil {
		t.Fatal("ptyRun должен вернуть ошибку на не-нулевом exit")
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("err = %v, want 'exit status 3'", err)
	}
	if !strings.Contains(out, "partial stdout before death") {
		t.Errorf("вывод перед смертью потерян: %q", out)
	}
}

// TestPtyRunTimeout — зависший ребёнок: ptyRun отдаёт ошибку в пределах
// таймаута + грейса, процесс реквизируется (SIGHUP по закрытию мастера,
// SIGKILL-страховка), читатель не течёт.
func TestPtyRunTimeout(t *testing.T) {
	start := time.Now()
	_, err := ptyHelper(t, "hang", 500*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ptyRun должен вернуть ошибку по таймауту")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("ptyRun висел %v — реквизиция не сработала", elapsed)
	}
}

// TestNdmcExecFailureSurface — склейка ERR-поверхности в ndmc(): на машине
// без /bin/ndmc (workstation) exec-провал обязан дать префикс "ERR(" —
// ndmExecFailed/ndmcFailed на этом стоят. Пропуск на роутере (ndmc есть —
// и трогать живой ndm из тестов нельзя).
func TestNdmcExecFailureSurface(t *testing.T) {
	if _, err := os.Stat("/bin/ndmc"); err == nil {
		t.Skip("/bin/ndmc существует (роутер?) — live-вызов из теста не делаем")
	}
	d := &Daemon{}
	out := d.ndmc("show running-config")
	if !strings.HasPrefix(out, "ERR(") {
		t.Fatalf("ndmc exec-fail = %q, want prefix ERR(", out)
	}
	if !ndmExecFailed(out) || !ndmcFailed(out) {
		t.Errorf("ndmExecFailed/ndmcFailed не увидели exec-провал: %q", out)
	}
}

// TestNdmcRejectsShellMetachars — defense-in-depth wave-1 D6 сохранён при
// переходе на прямой exec.
func TestNdmcRejectsShellMetachars(t *testing.T) {
	d := &Daemon{}
	for _, verb := range []string{"show running-config $(boom)", "show `boom`"} {
		out := d.ndmc(verb)
		if !strings.HasPrefix(out, "ERR(ndmc: cmd rejected") {
			t.Errorf("verb %q прошёл фильтр: %q", verb, out)
		}
	}
}
