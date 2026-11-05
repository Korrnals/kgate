package update

import "testing"

func TestParseVer(t *testing.T) {
	cases := []struct {
		in    string
		major int
		ok    bool
	}{
		{"v1.2.0", 1, true},
		{"1.2.0", 1, true},
		{"1.2.0-1", 1, true},
		{"v2.0.0-dev", 2, true},
		{"dev", 0, false},
		{"", 0, false},
		{"1.x.0", 0, false},
		{"1.2", 1, true},
	}
	for _, c := range cases {
		v, ok := parseVer(c.in)
		if ok != c.ok {
			t.Fatalf("parseVer(%q): ok=%v, want %v", c.in, ok, c.ok)
		}
		if ok && v[0] != c.major {
			t.Fatalf("parseVer(%q): major=%d, want %d", c.in, v[0], c.major)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.2", "v1.2.0", -1},
		{"v1.2.0", "v1.2.0", 0},
		{"1.3.0-1", "1.2.0", 1},
		{"dev", "v1.2.0", -1},     // lexicographic fallback: local build updates
		{"v0.9.9", "v0.10.0", -1}, // numeric, not lexicographic
		{"zzz", "aaa", 1},
	}
	for _, c := range cases {
		got := Compare(c.a, c.b)
		if got != c.want {
			t.Fatalf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPickAsset(t *testing.T) {
	rel := &Release{TagName: "v1.2.0", Assets: []Asset{
		{Name: "kgate_1.2.0_linux_amd64.tar.gz"},
		{Name: "kgate_1.2.0_linux_arm64.tar.gz"},
		{Name: "checksums-sha256.txt"},
	}}
	if a := rel.pickAsset("linux", "arm64"); a == nil || a.Name != "kgate_1.2.0_linux_arm64.tar.gz" {
		t.Fatalf("pickAsset arm64: %+v", a)
	}
	if a := rel.pickAsset("linux", "mips"); a != nil {
		t.Fatalf("pickAsset mips should miss, got %+v", a)
	}
	if a := rel.assetByName("checksums-sha256.txt"); a == nil {
		t.Fatal("assetByName(checksums) miss")
	}
}

func TestWantedSha(t *testing.T) {
	sums := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  kgate_1.2.0_linux_arm64.tar.gz\nbbbb  other\n")
	if got := wantedSha(sums, "kgate_1.2.0_linux_arm64.tar.gz"); got[:4] != "aaaa" {
		t.Fatalf("wantedSha=%q", got)
	}
	if got := wantedSha(sums, "missing.tar.gz"); got != "" {
		t.Fatalf("wantedSha miss should be empty, got %q", got)
	}
}

func TestArchiveName(t *testing.T) {
	if got := ArchiveName("1.2.0", "linux", "arm64"); got != "kgate_1.2.0_linux_arm64.tar.gz" {
		t.Fatalf("ArchiveName=%q", got)
	}
}
