package perf

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Budgets of CP-32 (SRS Appendix A), in the unit of each measurement.
const (
	BudgetDecisionMs   = 10.0  // FR-11.2, p95
	CeilingDecisionMs  = 100.0 // SEC ceiling
	BudgetCaptureMs    = 1.0   // FR-11.4, p95 difference
	BudgetOverheadMs   = 50.0  // FR-11.5, p95
	CeilingOverheadMs  = 250.0 // SEC ceiling
	BudgetQueryMs      = 2000.0
	BudgetIdleRSSBytes = 4 << 30 // FR-11.9
)

// Measurement is one FR-11 result.
type Measurement struct {
	Requirement string  `json:"requirement"`
	Name        string  `json:"name"`
	Metric      string  `json:"metric"`
	Unit        string  `json:"unit"`
	Value       float64 `json:"value"`
	Budget      float64 `json:"budget"`
	Ceiling     float64 `json:"ceiling,omitempty"`
	Samples     int     `json:"samples"`
	Pass        bool    `json:"pass"`
	// Complete reports that the measurement covers the requirement's whole
	// verification statement (the full sample count, duration or query
	// set); with the run on the recorded reference hardware a passing
	// complete measurement verifies its requirement.
	Complete bool   `json:"complete"`
	Method   string `json:"method"`
	Note     string `json:"note,omitempty"`
}

// Host describes the machine the measurements ran on.
type Host struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	CPUs      int    `json:"cpus"`
	CPU       string `json:"cpu,omitempty"`
	GoVersion string `json:"goVersion"`
	Runner    string `json:"runner,omitempty"`
	// MemoryBytes is the physical memory (MemTotal of /proc/meminfo).
	MemoryBytes int64 `json:"memoryBytes,omitempty"`
	// DiskBytes and DiskFreeBytes are the size and free space of the file
	// system that holds the work directory, DiskDevice its device and
	// DiskModel the device's model where the kernel reports one.
	DiskBytes  int64  `json:"diskBytes,omitempty"`
	DiskFree   int64  `json:"diskFreeBytes,omitempty"`
	DiskDevice string `json:"diskDevice,omitempty"`
	DiskModel  string `json:"diskModel,omitempty"`
	// RunnerEnvironment, Image and ImageVersion are the GitHub Actions
	// runner's RUNNER_ENVIRONMENT, ImageOS and ImageVersion.
	RunnerEnvironment string `json:"runnerEnvironment,omitempty"`
	Image             string `json:"image,omitempty"`
	ImageVersion      string `json:"imageVersion,omitempty"`
}

// Results is the perf.json document the status data publishes as
// "performance".
type Results struct {
	Schema      int    `json:"schema"`
	Commit      string `json:"commit"`
	GeneratedAt string `json:"generatedAt"`
	Host        Host   `json:"host"`
	// ReferenceHardware reports that the run was on the recorded reference
	// hardware of FR-11 (ReferenceClass, docs/reference-hardware.md), and
	// ReferenceClass then names it.
	ReferenceHardware bool          `json:"referenceHardware"`
	ReferenceClass    string        `json:"referenceClass,omitempty"`
	Dataset           Dataset       `json:"dataset"`
	Measurements      []Measurement `json:"measurements"`
}

// CurrentHost describes this machine; work is the directory whose file
// system is recorded as its disk.
func CurrentHost(work string) Host {
	h := Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), GoVersion: runtime.Version(), Runner: os.Getenv("RUNNER_NAME"),
		RunnerEnvironment: os.Getenv("RUNNER_ENVIRONMENT"), Image: os.Getenv("ImageOS"), ImageVersion: os.Getenv("ImageVersion")}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				h.CPU = strings.TrimSpace(v)
				break
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		h.MemoryBytes = memTotal(string(b))
	}
	h.DiskBytes, h.DiskFree, h.DiskDevice, h.DiskModel = diskOf(work)
	return h
}

// memTotal returns MemTotal of a /proc/meminfo text in bytes.
func memTotal(meminfo string) int64 {
	for _, l := range strings.Split(meminfo, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && k == "MemTotal" {
			var kb int64
			if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d kB", &kb); err == nil {
				return kb << 10
			}
		}
	}
	return 0
}

// The recorded reference hardware of FR-11 (docs/reference-hardware.md) is
// the GitHub-hosted standard Linux runner of the ubuntu-24.04 label for
// public repositories: x86_64, 4 processors, 16 GiB of memory, SSD. The
// processor model varies between runs of the class (AMD EPYC 7763, EPYC
// 9V74, Intel Xeon); each report records the one it ran on, with its
// memory and disk.
const (
	ReferenceClassName = "GitHub-hosted runner ubuntu-24.04, standard Linux class (x86_64, 4 vCPU, 16 GiB, SSD)"
	refCPUs            = 4
	// The runners report a MemTotal of about 15.6 GiB: 16 GiB less the
	// firmware and kernel reservations.
	refMemMin = 15 << 30
	refMemMax = 17 << 30
)

// ReferenceClass reports whether h is a machine of the recorded reference
// hardware class.
func ReferenceClass(h Host) bool {
	return h.OS == "linux" && h.Arch == "amd64" && h.CPUs == refCPUs && h.MemoryBytes >= refMemMin && h.MemoryBytes <= refMemMax &&
		h.RunnerEnvironment == "github-hosted" && h.Image == "ubuntu24"
}

// Quantile returns the q quantile (0 < q <= 1) of xs by the nearest-rank
// method.
func Quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	i := int(float64(len(s))*q+0.999999) - 1
	return s[min(max(i, 0), len(s)-1)]
}

// MeasureDecisions makes n decisions with callers concurrent callers
// against the compiled reference policy, as the Policy Decision Service
// (E-06) does for each call, and returns each decision's latency in
// milliseconds as the caller sees it (including waiting for the decider).
// Each caller is its own principal; sessions change every 500 calls.
func MeasureDecisions(doc []byte, n, callers int) ([]float64, error) {
	snap, err := policy.Compile(doc)
	if err != nil {
		return nil, err
	}
	d := policy.NewDecider(snap, 1<<30)
	lat := make([]float64, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	per := n / callers
	for c := range callers {
		lo, hi := c*per, (c+1)*per
		if c == callers-1 {
			hi = n
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				req := policy.Request{PrincipalID: fmt.Sprintf("workload-%d", c), SessionID: fmt.Sprintf("s-%d-%d", c, i/500), Profile: "dev",
					Template: "read-only", Server: "ref", Tool: RefTools[i%len(RefTools)], Arguments: json.RawMessage(`{"text":"x","path":"a.txt"}`)}
				t0 := time.Now()
				dec := d.Decide(req)
				lat[i] = float64(time.Since(t0).Nanoseconds()) / 1e6
				if dec.Outcome != policy.Permit {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("perf: decision %s (%s), want permit", dec.Outcome, dec.ReasonCode)
					}
					mu.Unlock()
					return
				}
				if len(dec.ConsideredRules) < RefCandidates {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("perf: decision considered %d rules, want %d", len(dec.ConsideredRules), RefCandidates)
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	return lat, firstErr
}

// WriteTestJSON writes the measurements as `go test -json` events, one
// test per measurement under package pkg, so tools/reqreport counts them:
// a measurement within its budget is a claim of its requirement, full when
// reference is true (the run was on the recorded reference hardware) and
// the measurement is complete, partial otherwise; one over its budget is a
// failing test. The status job merges this file with the Go results.
func WriteTestJSON(w io.Writer, pkg string, ms []Measurement, reference bool, at time.Time) error {
	enc := json.NewEncoder(w)
	ts := at.UTC().Format(time.RFC3339Nano)
	failed := false
	for _, m := range ms {
		name := "TestPerf" + strings.NewReplacer("-", "_", ".", "_").Replace(m.Requirement)
		action := "pass"
		if !m.Pass {
			action, failed = "fail", true
		}
		out := fmt.Sprintf("    perf: %s %s %s = %.3f %s (budget %.3f %s, %d samples): %s\n", m.Requirement, m.Name, m.Metric, m.Value, m.Unit, m.Budget, m.Unit, m.Samples, m.Method)
		for _, ev := range []map[string]any{
			{"Time": ts, "Action": "run", "Package": pkg, "Test": name},
			{"Time": ts, "Action": "output", "Package": pkg, "Test": name, "Output": out},
			{"Time": ts, "Action": "output", "Package": pkg, "Test": name, "Output": "    " + marker(m, reference) + " " + m.Requirement + "\n"},
			{"Time": ts, "Action": action, "Package": pkg, "Test": name, "Elapsed": 0},
		} {
			if err := enc.Encode(ev); err != nil {
				return err
			}
		}
	}
	end := "pass"
	if failed {
		end = "fail"
	}
	return enc.Encode(map[string]any{"Time": ts, "Action": end, "Package": pkg})
}

// marker is the claim of a measurement: VERIFIES for a complete
// measurement on the reference hardware, PARTIAL otherwise.
func marker(m Measurement, reference bool) string {
	if reference && m.Complete {
		return "VERIFIES:"
	}
	return "PARTIAL:"
}
