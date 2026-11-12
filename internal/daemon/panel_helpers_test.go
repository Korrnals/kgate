package daemon

// Тестовые хелперы панели — тонкие обёртки, чтобы panel_test.go не тянул
// лишние импорты (os).

import "os"

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0644)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
