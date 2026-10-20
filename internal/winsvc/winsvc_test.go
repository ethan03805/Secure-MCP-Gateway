package winsvc

import (
	"encoding/xml"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCommandLineQuoting(t *testing.T) {
	cases := map[string][]string{
		`a b`:                         {"a", "b"},
		`"C:\Program Files\x" -c`:     {`C:\Program Files\x`, "-c"},
		`"a\"b"`:                      {`a"b`},
		`"a\\\"b"`:                    {`a\"b`},
		`"end s\\"`:                   {`end s\`},
		`ends\`:                       {`ends\`},
		`""`:                          {""},
		`C:\dir\smcpd.exe -supervise`: {`C:\dir\smcpd.exe`, "-supervise"},
		`"tab	x"`:                     {"tab\tx"},
	}
	for want, args := range cases {
		if got := CommandLine(args...); got != want {
			t.Errorf("CommandLine(%q) = %s, want %s", args, got, want)
		}
	}
}

func TestStopEventName(t *testing.T) {
	a := StopEventName(`C:\Users\a\AppData\Local\smcp-gateway\config\smcp.toml`)
	if !strings.HasPrefix(a, `Local\smcp-gateway-stop-`) || len(a) != len(`Local\smcp-gateway-stop-`)+16 {
		t.Fatalf("name %q", a)
	}
	if b := StopEventName(`C:\Users\b\AppData\Local\smcp-gateway\config\smcp.toml`); b == a {
		t.Fatal("two installations share a stop event")
	}
}

func TestTaskXML(t *testing.T) {
	b, err := TaskXML("S-1-5-21-1-2-3-1001", `C:\Users\a b\smcpd.exe`, `C:\Users\a b\cfg & co\smcp.toml`, `C:\Users\a b`)
	if err != nil {
		t.Fatal(err)
	}
	// Well-formed, with the values escaped.
	var doc struct {
		Triggers struct {
			Logon struct {
				UserID string `xml:"UserId"`
			} `xml:"LogonTrigger"`
		} `xml:"Triggers"`
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Actions>Exec"`
	}
	dec := xml.NewDecoder(strings.NewReader(strings.Replace(string(b), `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if doc.Triggers.Logon.UserID != "S-1-5-21-1-2-3-1001" || doc.Exec.Command != `C:\Users\a b\smcpd.exe` ||
		doc.Exec.Arguments != `-supervise -config "C:\Users\a b\cfg & co\smcp.toml"` {
		t.Fatalf("%+v", doc)
	}
	f := TaskFile(b)
	if f[0] != 0xff || f[1] != 0xfe {
		t.Fatal("no byte order mark")
	}
	u := make([]uint16, 0, len(f)/2)
	for i := 2; i < len(f); i += 2 {
		u = append(u, uint16(f[i])|uint16(f[i+1])<<8)
	}
	if string(utf16.Decode(u)) != string(b) {
		t.Fatal("UTF-16 round trip")
	}
	if _, err := TaskXML("", "x", "y", "z"); err == nil {
		t.Fatal("empty SID accepted")
	}
}

func TestCheckVersion(t *testing.T) {
	for _, c := range []struct {
		v  Version
		ok bool
	}{
		{Version{Major: 10, Build: 22631}, true},
		{Version{Major: 10, Build: 22630}, false},
		{Version{Major: 10, Build: 20348, Server: true}, true},
		{Version{Major: 10, Build: 20347, Server: true}, false},
		{Version{Major: 10, Build: 20348}, false}, // a client build below 23H2
		{Version{Major: 6, Build: 30000}, false},
	} {
		if err := CheckVersion(c.v); (err == nil) != c.ok {
			t.Errorf("%v: %v", c.v, err)
		}
	}
}
