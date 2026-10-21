package connector_test

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// memScan is run as root: it reads the memory of every process in the PID
// namespace of the container whose init has the PID argv[1], looking for
// the bytes on stdin, and prints how many processes it read and the PID
// that holds them ("" when none).
const memScan = `import os,sys,re
init=sys.argv[1]
v=sys.stdin.buffer.read()
ns=os.readlink('/proc/%s/ns/pid'%init)
hit=''
n=0
for p in os.listdir('/proc'):
    if not p.isdigit(): continue
    try:
        if os.readlink('/proc/%s/ns/pid'%p)!=ns: continue
        maps=open('/proc/%s/maps'%p).read().splitlines()
        mem=open('/proc/%s/mem'%p,'rb',0)
    except OSError:
        continue
    n+=1
    for l in maps:
        m=re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+)',l)
        if not m or m.group(3)[0]!='r': continue
        a,b=int(m.group(1),16),int(m.group(2),16)
        try:
            mem.seek(a); chunk=mem.read(b-a)
        except (OSError,ValueError,OverflowError):
            continue
        if v in chunk: hit=p
print('processes',n)
print('hit',hit)
`

// secretInMemory scans the memory of every process of the container for
// value, as root (sudo -n, Linux). It returns the PID holding it ("" when
// none) and whether the scan ran. The value is never printed.
func secretInMemory(t *testing.T, eng, ctr, value string) (string, bool) {
	t.Helper()
	if runtime.GOOS != "linux" || exec.Command("sudo", "-n", "true").Run() != nil {
		t.Log("memory not scanned: needs Linux and sudo")
		return "", false
	}
	out, err := exec.Command(eng, "inspect", "--format", "{{.State.Pid}}", ctr).Output()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sudo", "-n", "python3", "-c", memScan, strings.TrimSpace(string(out)))
	cmd.Stdin = strings.NewReader(value)
	res, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("memory scan: %v", err)
	}
	t.Logf("memory scan: %s", strings.ReplaceAll(strings.TrimSpace(string(res)), "\n", "; "))
	for _, l := range strings.Split(string(res), "\n") {
		if strings.HasPrefix(l, "processes 0") {
			t.Fatal("the memory scan found no process of the instance")
		}
		if h, ok := strings.CutPrefix(l, "hit "); ok {
			return strings.TrimSpace(h), true
		}
	}
	return "", true
}
