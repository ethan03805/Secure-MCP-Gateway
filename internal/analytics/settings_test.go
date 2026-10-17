package analytics

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

func parse(t *testing.T, obs string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("[state]\ndir = \"/tmp/smcp-test-state\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[policy]\nfile = \"p.json\"\n[observation]\n" + obs))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestResolveDefaults(t *testing.T) {
	s, err := Resolve(parse(t, ""), observe.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled || s.SamplingRate != 0.1 || s.Retention != 90*24*time.Hour || s.Scoring != "async" || s.RequireApproval != "off" ||
		s.Thresholds.Elevated != 2 || s.Thresholds.Critical != 4 || s.Baseline.NMin != 30 || s.FlushRecords != 1000 ||
		s.FlushInterval != 200*time.Millisecond || s.MetricsInterval != 10*time.Second || s.MemoryLimit != 512<<20 ||
		s.Dir != filepath.Join("/tmp/smcp-test-state", "observation") || len(s.Baseline.Features) != len(DefaultFeatures) {
		t.Fatalf("defaults %+v", s)
	}
	for _, p := range s.Parameters {
		par, _ := observe.DefaultCatalog().Lookup(p)
		if par.Sensitivity != "S0" && par.Sensitivity != "S1" {
			t.Fatalf("default parameter %s is %s", p, par.Sensitivity)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	for obs, want := range map[string]string{
		`parameters = ["P-999"]`:                                      "unknown parameter",
		`parameters = ["P-145"]`:                                      "S3",
		`parameters = ["P-240"]`:                                      "periodic",
		`require_approval_band = "abnormal"`:                          "scoring",
		"[observation.baseline]\nbands = [3, 2, 4]":                   "elevated < abnormal",
		"[[observation.baseline.feature]]\nparameter = \"tool_name\"": "not numeric",
		"[[observation.baseline.feature]]\nparameter = \"tool_name\"\nkind = \"categorical\"": "",
	} {
		_, err := Resolve(parse(t, obs), observe.DefaultCatalog())
		if want == "" {
			if err != nil {
				t.Fatalf("%q: %v", obs, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: %v, want %q", obs, err, want)
		}
	}
}

func TestDisabledService(t *testing.T) {
	cfg := parse(t, "enabled = false")
	s, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Disabled() || s.Observer() != nil {
		t.Fatal("disabled service observes")
	}
	f := pipeline.NewFilters()
	if err := s.RegisterFilters(f); err != nil || len(f.Unavailable([]string{"observe-request"})) != 1 {
		t.Fatal("disabled service registered filters")
	}
	s.Close()
}

func TestStoreUnavailableDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	cfg := parse(t, `store = "duckdb"`)
	cfg.State.Dir = dir
	s, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if s.Disabled() || s.Observer() == nil {
		t.Fatal("service not running")
	}
	// With cgo the store opens; without it the service runs without storage.
	if s.Store == nil && s.storeErr == nil {
		t.Fatal("no store and no error")
	}
	s.Close()
}
