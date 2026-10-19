package winpath

import "testing"

func TestIsAbs(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\data\proj`: true, `c:/data`: true, `\etc\passwd`: true, `/etc/passwd`: true,
		`C:`: false, `C:x`: false, `x\y`: false, `..\..\x`: false, ``: false, `~`: false,
	} {
		if got := IsAbs(p); got != want {
			t.Errorf("IsAbs(%q) = %v", p, got)
		}
	}
}

func TestRefused(t *testing.T) {
	for p, want := range map[string]string{
		`C:\data\proj\x`:            "",
		`c:\DATA\Proj\x`:            "",
		`C:\data\proj\a.txt`:        "",
		`C:\data\proj\a.txt:hidden`: RuleStream,
		`C:\data\proj\a.txt::$DATA`: RuleStream,
		`C:\data\proj\NUL`:          RuleDeviceName,
		`C:\data\proj\nul.txt`:      RuleDeviceName,
		`C:\data\proj\COM1`:         RuleDeviceName,
		`C:\data\proj\lpt9.log`:     RuleDeviceName,
		`C:\data\proj\CON \x`:       RuleDeviceName,
		`C:\data\proj\COM10`:        "",
		`C:\data\proj\console`:      "",
		`\\?\C:\Windows`:            RuleDevicePrefix,
		`\\.\PhysicalDrive0`:        RuleDevicePrefix,
		`//?/C:/Windows`:            RuleDevicePrefix,
		`\??\C:\Windows`:            RuleDevicePrefix,
		`\\host\share`:              RuleUNC,
		`//host/share/x`:            RuleUNC,
		`C:x`:                       RuleDriveRelative,
		`C:`:                        RuleDriveRelative,
		`/etc/passwd`:               "",
	} {
		if got := Refused(p); got != want {
			t.Errorf("Refused(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestWithin(t *testing.T) {
	root := `C:\data\proj`
	for p, want := range map[string]bool{
		`C:\data\proj`: true, `c:\DATA\Proj\x`: true, `C:/data/proj/x/y`: true, `C:\data\proj\`: true,
		`C:\data\project`: false, `C:\data`: false, `D:\data\proj\x`: false, `\data\proj\x`: false,
	} {
		if got := Within(p, root); got != want {
			t.Errorf("Within(%q, %q) = %v", p, root, got)
		}
	}
	if !Within(`C:\x`, `C:\`) || Within(`D:\x`, `C:\`) {
		t.Fatal("drive root")
	}
}
