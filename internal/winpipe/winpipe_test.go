package winpipe

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

func TestEntries(t *testing.T) {
	e := Entries("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-2000", "")
	if len(e) != 4 {
		t.Fatalf("entries %v", e)
	}
	if !e[0].Deny || e[0].SID != winsec.SIDNetwork || !e[1].Deny || e[1].SID != winsec.SIDAnonymous {
		t.Fatalf("deny entries first: %v", e)
	}
	if e[2].SID != "S-1-5-21-1-2-3-1001" || e[2].Access&0x4 == 0 {
		t.Fatalf("server entry may create instances: %v", e[2])
	}
	if e[3].SID != "S-1-5-21-1-2-3-2000" || e[3].Access&0x4 != 0 || e[3].Access&0x3 != 0x3 {
		t.Fatalf("client entry reads and writes but creates no instance: %v", e[3])
	}
	if Name("") != `\\.\pipe\smcp-harness` || Name("S-1-5-21-9") != `\\.\pipe\smcp-harness-S-1-5-21-9` {
		t.Fatal("CP-02 names")
	}
}
