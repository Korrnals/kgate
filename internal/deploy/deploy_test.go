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

// wave-3 N-7: замкнутое множество эхо детекта — пустой вывод или мусор
// (транзиентный сбой транспорта ssh) НЕ считаются детектированными;
// destroy обязан отказать, а не продолжать вслепую.
func TestPlatformDetectKnown(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"openwrt", true},
		{"non-openwrt", true},
		{"openwrt\n", true},
		{"  non-openwrt  ", true},
		{"", false},
		{"\n", false},
		{"мусор", false},
		{"openwrt non-openwrt", false},
		{"OpenWrt", false},
	}
	for _, c := range cases {
		if got := platformDetectKnown(c.out); got != c.want {
			t.Fatalf("platformDetectKnown(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}
