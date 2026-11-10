package deploy

import "testing"

// wave-2 F1: детект платформы для destroy — ТОЧНОЕ сравнение после TrimSpace.
// Подстрока "openwrt" матчит и "non-openwrt" — эхо Keenetic/Entware (основной
// платформы), из-за чего destroy детерминированно отказывал там, где он
// легитимен.
func TestPlatformIsOpenWrt(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"openwrt", true},
		{"openwrt\n", true},
		{"  openwrt  ", true},
		{"non-openwrt", false},
		{"", false},
		{"\n", false},
	}
	for _, c := range cases {
		if got := platformIsOpenWrt(c.out); got != c.want {
			t.Fatalf("platformIsOpenWrt(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}
