package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type fakeService struct {
	unit           *unitFile
	machineRunning bool
	machineExists  bool
	perUserRunning bool
	perUserCfg     string
	statusErr      error
	controlErr     error
	calls          []string
}

func (f *fakeService) probes() serviceProbes {
	return serviceProbes{
		machine: func() (bool, bool, error) { return f.machineRunning, f.machineExists, nil },
		perUser: func(cfg string) (bool, error) { f.perUserCfg = cfg; return f.perUserRunning, nil },
		run: func(argv []string) error {
			f.calls = append(f.calls, "status "+strings.Join(argv, " "))
			return f.statusErr
		},
		unit: func(cfgDir string) *unitFile {
			f.calls = append(f.calls, "unit "+cfgDir)
			return f.unit
		},
		control: func(cfgDir, action string) error {
			f.calls = append(f.calls, action)
			return f.controlErr
		},
	}
}

func runService(t *testing.T, goos string, f *fakeService, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := serviceRun(goos, args, &out, f.probes())
	return strings.TrimSpace(out.String()), err
}

// TestServiceStatusPerPlatform: `smcpctl service status` names the state of
// each kind of installation in one word, without changing anything
// (FR-20.3: the Desktop Application's status query on Windows).
func TestServiceStatusPerPlatform(t *testing.T) {
	reqtest.Partial(t, "FR-20.3")
	cfgDir := filepath.Join(t.TempDir(), "config")
	task := &unitFile{path: filepath.Join(cfgDir, winTaskFile), kind: "win-task", exists: true}
	for _, c := range []struct {
		name string
		goos string
		f    fakeService
		want string
	}{
		{"per-user running", "windows", fakeService{unit: task, perUserRunning: true}, "running"},
		{"per-user stopped", "windows", fakeService{unit: task}, "stopped"},
		{"machine running", "windows", fakeService{unit: &unitFile{kind: "win-service", exists: true}, machineRunning: true, machineExists: true}, "running"},
		{"machine definition unreadable, service registered", "windows", fakeService{machineExists: true}, "stopped"},
		{"nothing on windows", "windows", fakeService{}, "not-installed"},
		{"nothing on linux", "linux", fakeService{machineExists: true}, "not-installed"},
		{"systemd active", "linux", fakeService{unit: &unitFile{kind: "systemd-user", exists: true}}, "running"},
		{"systemd inactive", "linux", fakeService{unit: &unitFile{kind: "systemd-system", exists: true}, statusErr: errors.New("exit 3")}, "stopped"},
		{"launchd loaded", "darwin", fakeService{unit: &unitFile{kind: "launchd", exists: true}}, "running"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := c.f
			got, err := runService(t, c.goos, &f, "status", "--config", filepath.Join(cfgDir, "smcp.toml"))
			if err != nil || got != c.want {
				t.Fatalf("status = %q, %v; want %q", got, err, c.want)
			}
			for _, call := range f.calls {
				if call == "start" || call == "stop" {
					t.Fatalf("status changed the service: %v", f.calls)
				}
			}
			if f.unit != nil && f.unit.kind == "win-task" && f.perUserCfg != filepath.Join(cfgDir, "smcp.toml") {
				t.Fatalf("per-user check used %q", f.perUserCfg)
			}
		})
	}
	f := fakeService{unit: &unitFile{kind: "systemd-user", exists: true}}
	if _, err := runService(t, "linux", &f, "status"); err != nil {
		t.Fatal(err)
	}
	want := []string{"unit ", "status systemctl --user is-active --quiet smcpd.service"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %q, want %q", f.calls, want)
	}
}

// TestServiceActions: start does nothing when the service runs (a second
// per-user supervisor would fight the first), restart stops only a
// running service, and nothing is done without an installation.
func TestServiceActions(t *testing.T) {
	reqtest.Partial(t, "FR-20.3")
	task := &unitFile{path: filepath.Join(t.TempDir(), winTaskFile), kind: "win-task", exists: true}
	for _, c := range []struct {
		args    []string
		running bool
		want    []string
		out     string
	}{
		{[]string{"start"}, false, []string{"start"}, "started"},
		{[]string{"start"}, true, nil, "running"},
		{[]string{"stop"}, true, []string{"stop"}, "stopped"},
		{[]string{"stop"}, false, []string{"stop"}, "stopped"},
		{[]string{"restart"}, true, []string{"stop", "start"}, "restarted"},
		{[]string{"restart"}, false, []string{"start"}, "restarted"},
	} {
		f := fakeService{unit: task, perUserRunning: c.running}
		out, err := runService(t, "windows", &f, c.args...)
		if err != nil || out != c.out {
			t.Fatalf("%v (running %v) = %q, %v", c.args, c.running, out, err)
		}
		var actions []string
		for _, call := range f.calls {
			if call == "start" || call == "stop" {
				actions = append(actions, call)
			}
		}
		if !reflect.DeepEqual(actions, c.want) {
			t.Fatalf("%v (running %v): actions %v, want %v", c.args, c.running, actions, c.want)
		}
	}
	f := fakeService{}
	if _, err := runService(t, "windows", &f, "start"); !errors.Is(err, errNoManager) {
		t.Fatalf("start without installation: %v", err)
	}
	for _, bad := range [][]string{nil, {"enable"}, {"status", "extra"}, {"start", "--unknown"}} {
		if _, err := runService(t, "linux", &fakeService{}, bad...); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// TestServiceWin32ExitCode: a Win32 error from the service manager ends
// smcpctl with the customer-code bit and the code, so an elevated caller
// that cannot read the output can show the system's text (FR-20.3).
func TestServiceWin32ExitCode(t *testing.T) {
	reqtest.Partial(t, "FR-20.3")
	task := &unitFile{kind: "win-service", exists: true}
	f := fakeService{unit: task, machineExists: true, controlErr: errors.Join(errors.New("winsvc: start"), syscall.Errno(1058))}
	_, err := runService(t, "windows", &f, "start")
	var ec interface{ smcpctlExitCode() int }
	if !errors.As(err, &ec) || ec.smcpctlExitCode() != 0x20000000|1058 {
		t.Fatalf("err = %v", err)
	}
	f = fakeService{unit: &unitFile{kind: "systemd-user", exists: true}, statusErr: errors.New("inactive"), controlErr: syscall.Errno(5)}
	_, err = runService(t, "linux", &f, "start")
	if errors.As(err, &ec) {
		t.Fatalf("exit code carried off Windows: %v", err)
	}
	f = fakeService{unit: task, machineExists: true, controlErr: errors.New("plain")}
	_, err = runService(t, "windows", &f, "start")
	if err == nil || errors.As(err, &ec) {
		t.Fatalf("plain error: %v", err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"service"}, &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("usage exit %d", code)
	}
}
