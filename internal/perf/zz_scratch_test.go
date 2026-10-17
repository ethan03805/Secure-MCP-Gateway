package perf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"syscall"
	"time"
)

func TestScratchCapture(t *testing.T) {
	bin := os.Getenv("SCRATCH_BIN")
	if bin == "" {
		t.Skip()
	}
	doc, err := ReferencePolicy("workload-r1", RefRules, RefCandidates)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	calls := 800
	conds := strings.Split(os.Getenv("SCRATCH_CONDS"), ",")
	for i, extra := range conds {
		env, extra, _ := strings.Cut(extra, ";")
		extra = strings.ReplaceAll(extra, `\n`, "\n")
		for _, k := range []string{"SCRATCH_NOSPANS", "SCRATCH_NOLOCK", "SCRATCH_X1", "SCRATCH_X2", "SCRATCH_X3"} {
			os.Unsetenv(k)
		}
		for _, kv := range strings.Fields(env) {
			k, v, _ := strings.Cut(kv, "=")
			os.Setenv(k, v)
		}
		in, err := newInstance(bin, filepath.Join(work, fmt.Sprint(i)), extra, doc)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(in.sandbox, "64k.txt"), []byte(strings.Repeat("0123456789abcdef", 64<<10/16)), 0o644)
		if pd := os.Getenv("SCRATCH_PROF"); pd != "" {
			d := filepath.Join(pd, fmt.Sprint(i))
			os.MkdirAll(d, 0o755)
			os.Setenv("SCRATCH_PROF_DIR", d)
		}
		if err := in.start(); err != nil {
			t.Fatal(err)
		}
		if err := drive(context.Background(), in, calls, 8); err != nil {
			t.Logf("cond %d drive: %v", i, err)
		}
		if os.Getenv("SCRATCH_PROF") != "" {
			in.cmd.Process.Signal(syscall.SIGUSR1)
			time.Sleep(2 * time.Second)
		}
		in.stop()
		lat, _ := in.overheads()
		t.Logf("cond %d %s %q: n=%d p50=%.3f p95=%.3f", i, env, extra, len(lat), Quantile(lat, 0.5), Quantile(lat, 0.95))
	}
}
