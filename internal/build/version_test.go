package build

import "testing"

// Version прошит ldflags "-X kgate/internal/build.Version=$(VERSION)";
// дефолт без ldflags — "dev" (локальные сборки честно помечены dev).
func TestVersionDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("build.Version пуст — единый источник версии сломан")
	}
	if Version != "dev" { // тестовый прогон без ldflags
		t.Logf("build.Version = %q (вшита ldflags)", Version)
	}
}
