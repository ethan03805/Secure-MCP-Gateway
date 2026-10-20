package winport

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const root = "../.."

// reviewed lists the POSIX-mode, owner and signal reads in code compiled
// for Windows that are not guarded by a runtime.GOOS branch, keyed by
// "file:function", each with the reason it is not a security check on
// Windows or what replaces it there. A new unguarded read fails
// TestWindowsPOSIXReadsReviewed until it is guarded or listed here.
var reviewed = map[string]string{
	// Not security checks: a mode copied, reported or used to mark a file
	// executable, a socket or a link.
	"cmd/smcpctl/install.go:(*installer).ensureDir": "reports an existing directory's mode in the Linux and macOS install plan; the Windows plan (install_windows.go) writes the CP-46 DACLs with winsec instead",
	"cmd/smcpctl/release.go:extractRelease":         "copies the executable bit of a release tar entry; the signature and digest checks decide trust",
	"internal/backup/backup.go:Extract":             "restores a non-public entry owner-only (0600); never makes a file more open, and on Windows the state directory's DACL of FR-21.5 applies",
	"internal/harness/harness.go:Apply":             "keeps a client configuration file's existing mode when it is rewritten",
	"internal/harness/harness.go:Remove":            "keeps a client configuration file's existing mode when it is restored",
	"internal/packaging/archive.go:TreeDigest":      "the executable bit is part of the package tree digest on every platform; the digest is compared, not trusted",
	"internal/packaging/archive.go:TarGzDir":        "copies the executable bit into a package archive",
	"internal/packaging/archive.go:ExtractTarGz":    "restores the executable bit of a package entry",
	"internal/packaging/archive.go:MakeWritable":    "adds the owner write bit so an unpacked tree can be removed",
	"internal/filters/paths.go:resolveDepth":        "detects a symbolic link (ModeSymlink), not a permission; on Windows the path rules of FR-21.25 also refuse links outside the root",
	"internal/edge/uds.go:(*Gateway).ListenUDS":     "detects a stale socket file; on Windows listenPlatform returns the CP-02 named pipe first (uds_windows.go, FR-21.8)",
	"internal/testperm/testperm.go:check":           "test helper for POSIX modes; its Windows callers skip it",
	"scripts/agents/clients.go:findBin":             "test tooling: finds an executable client binary",
	// POSIX owners on paths Windows never takes: launchd, systemd, sudo,
	// nftables and Podman exist only on macOS and Linux. On Windows
	// os.Getuid and os.Geteuid return -1, so a Windows run that reached
	// one of them would see "not root".
	"cmd/smcpctl/install.go:chownPath":                           "chown of the Linux system-unit directories; Windows installs set DACLs (install_windows.go)",
	"cmd/smcpctl/service.go:managerCmd":                          "launchd target of the macOS service (case launchd)",
	"cmd/smcpctl/servicecmd.go:statusArgv":                       "launchd target of the macOS service (case launchd)",
	"cmd/smcpctl/uninstall.go:uninstallCmd":                      "launchd target of the macOS service (case launchd)",
	"cmd/smcpctl/uninstall.go:asRoot":                            "sudo prefix for Linux system units; Windows units are removed through the Service Control Manager and Task Scheduler",
	"cmd/smcpctl/remote.go:remoteEnable":                         "chooses the error text after nftables failed (Linux remote access); not a check",
	"internal/profile/profile.go:DetectHost":                     "rootless Podman detection for the Enforced prerequisites; DetectHost returns before it on Windows (Standalone, SR-4-2)",
	"internal/sandbox/doctor.go:Doctor":                          "Enforced prerequisites report of the Linux sandbox (Podman)",
	"internal/sandbox/runner.go:lookupRunAs":                     "Linux sandbox run-as user (Podman)",
	"internal/sandbox/secretacl.go:(*Launcher).grantTraversal":   "Linux POSIX ACLs on secret files for the sandbox user",
	"internal/sandbox/secretacl.go:(*Launcher).grantSecretFiles": "Linux POSIX ACLs on secret files for the sandbox user",
	"internal/sandbox/secretacl.go:(*Launcher).instanceUID":      "Linux POSIX ACLs on secret files for the sandbox user",
	"internal/sandbox/spec.go:CheckMountSource":                  "Podman socket mount check of the Linux sandbox",
	"internal/sandbox/probe/probe.go:Server":                     "diagnostic probe that reports its own uid inside the Linux sandbox",
	"scripts/agents/lockdown.go:rootRunner":                      "test tooling: the Linux lockdown run uses sudo",
	"cmd/smcpctl/install.go:newInstaller":                        "the uid selects the Linux and macOS service units; installWindows ignores it",
	"internal/backup/backup.go:addFile":                          "records the file mode in the archive header so a restore on Linux or macOS reproduces it",
	// Guarded by a per-platform constant instead of runtime.GOOS.
	"internal/keys/perms.go:CheckPrivate": "returns checkPlatform first when modeChecked is false, which it is on Windows (protect_windows.go): DPAPI blobs and the state DACL (FR-21.10, FR-21.5)",
}

// finding is one unguarded read.
type finding struct {
	key, pos, what string
}

// TestWindowsPOSIXReadsReviewed checks the second half of FR-21.2 on the
// files that GOOS=windows compiles: every read of a POSIX permission mode
// (Mode().Perm(), Mode()&bits, a tar header's Mode&bits), a POSIX owner
// (os.Getuid, os.Geteuid, user.User.Uid, syscall.Stat_t) or a Unix signal
// result (WaitStatus, Signaled) either sits in a branch that tests
// runtime.GOOS (so Windows takes another branch, the FR-21 counterpart or
// a refusal) or is listed in reviewed with the reason it is not a
// security check on Windows. Listed entries that no longer occur fail the
// test too, so the list stays exact.
func TestWindowsPOSIXReadsReviewed(t *testing.T) {
	reqtest.Partial(t, "FR-21.2") // the full claim is TestWindowsBuildPortability's
	checkPOSIXReads(t)
}

func checkPOSIXReads(t *testing.T) {
	t.Helper()
	got := scanWindowsFiles(t)
	seen := map[string]bool{}
	var bad []string
	for _, f := range got {
		seen[f.key] = true
		if _, ok := reviewed[f.key]; !ok {
			bad = append(bad, fmt.Sprintf("%s: %s in %s", f.pos, f.what, f.key))
		}
	}
	for k := range reviewed {
		if !seen[k] {
			bad = append(bad, "reviewed entry no longer occurs (remove it): "+k)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("POSIX mode, owner or signal reads in code compiled for Windows without a runtime.GOOS branch (guard them, or add them to reviewed with the reason):\n%s", strings.Join(bad, "\n"))
	}
	t.Logf("%d unguarded reads, all reviewed", len(got))
}

// TestWindowsBuildPortability performs the FR-21.2 verification on a
// Windows CI runner: every package, commands and test packages included,
// builds and passes go vet for windows/amd64 and windows/arm64 with
// CGO_ENABLED=0 (go vet type-checks the test files), and the POSIX reads
// are reviewed (TestWindowsPOSIXReadsReviewed). The fail-closed and
// counterpart tests the statement names run in the same job:
// internal/keys (DACL and DPAPI in place of CheckPrivate's mode check),
// internal/pipeline (CreateProcess launcher) and internal/edge with
// internal/winpipe (named pipe in place of the UDS listener). Elsewhere
// it runs only with SMCP_WINPORT=1 and then claims nothing.
func TestWindowsBuildPortability(t *testing.T) {
	onWindows := runtime.GOOS == "windows"
	if !onWindows && os.Getenv("SMCP_WINPORT") != "1" {
		t.Skip("runs on a Windows CI runner (or with SMCP_WINPORT=1)")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, args := range [][]string{{"build", "./..."}, {"vet", "./..."}} {
			cmd := exec.Command("go", args...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("GOOS=windows GOARCH=%s go %s: %v\n%s", arch, strings.Join(args, " "), err, out)
			}
			t.Logf("GOOS=windows GOARCH=%s CGO_ENABLED=0 go %s: ok", arch, strings.Join(args, " "))
		}
	}
	// The commands the statement names are main packages of ./cmd.
	for _, c := range []string{"smcpd", "smcpctl", "smcp-session", "smcp-stdio", "smcp-connect", "smcp-refserver", "smcp-hostile", "smcp-workload"} {
		if _, err := os.Stat(filepath.Join(root, "cmd", c)); err != nil {
			t.Fatalf("command %s: %v", c, err)
		}
	}
	checkPOSIXReads(t)
	if onWindows {
		reqtest.Verifies(t, "FR-21.2")
	}
}

// scanWindowsFiles parses every non-test Go file that GOOS=windows
// compiles (build constraints and file-name suffixes applied) and returns
// the unguarded POSIX reads.
func scanWindowsFiles(t *testing.T) []finding {
	t.Helper()
	ctx := build.Default
	ctx.GOOS = "windows"
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false
	var out []finding
	fset := token.NewFileSet()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(abs, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if dir != abs && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "node_modules" || name == "vendor") {
			return filepath.SkipDir
		}
		// Other modules (desktop, spikes, archive) have their own go.mod.
		if dir != abs {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return filepath.SkipDir
			}
		}
		pkg, err := ctx.ImportDir(dir, 0)
		if err != nil {
			return nil // no Go files for windows here
		}
		for _, f := range pkg.GoFiles {
			p := filepath.Join(dir, f)
			file, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(abs, p)
			out = append(out, scanFile(fset, filepath.ToSlash(rel), file)...)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("the scan found no POSIX reads at all; the scanner is broken")
	}
	return out
}

func scanFile(fset *token.FileSet, rel string, file *ast.File) []finding {
	var out []finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		key := rel + ":" + funcName(fn)
		var stack []ast.Node
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			if what := posixRead(n); what != "" && !guarded(stack) {
				out = append(out, finding{key: key, pos: fset.Position(n.Pos()).String(), what: what})
			}
			return true
		})
	}
	return out
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	var b strings.Builder
	switch r := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := r.X.(*ast.Ident); ok {
			b.WriteString("(*" + id.Name + ")")
		}
	case *ast.Ident:
		b.WriteString(r.Name)
	}
	return b.String() + "." + fn.Name.Name
}

// posixRead names the POSIX read at n, or returns "".
func posixRead(n ast.Node) string {
	switch x := n.(type) {
	case *ast.BinaryExpr:
		if x.Op == token.AND && (isModeExpr(x.X) || isModeExpr(x.Y)) {
			return "mode bits"
		}
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "Perm":
				if isModeCall(sel.X) {
					return "Mode().Perm()"
				}
			case "Getuid", "Geteuid", "Getgid":
				if isIdent(sel.X, "os") {
					return "os." + sel.Sel.Name
				}
			case "Signaled":
				return "Signaled()"
			}
		}
	case *ast.SelectorExpr:
		if isIdent(x.X, "syscall") && (x.Sel.Name == "Stat_t" || x.Sel.Name == "WaitStatus") {
			return "syscall." + x.Sel.Name
		}
		if x.Sel.Name == "Uid" {
			return ".Uid"
		}
	}
	return ""
}

// isModeExpr reports an expression that yields a file mode: x.Mode(),
// x.Mode().Perm(), or a tar header's x.Mode.
func isModeExpr(e ast.Expr) bool {
	if p, ok := e.(*ast.ParenExpr); ok {
		return isModeExpr(p.X)
	}
	if isModeCall(e) {
		return true
	}
	if c, ok := e.(*ast.CallExpr); ok {
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Perm" && isModeCall(sel.X) {
			return true
		}
	}
	if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == "Mode" {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && (id.Name == "perm" || id.Name == "mode") {
		return false // a local copy is caught where it is read from Mode()
	}
	return false
}

func isModeCall(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Mode" && len(c.Args) == 0
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// guarded reports whether the innermost node of stack sits in a branch of
// an if statement (or a switch case) whose condition tests runtime.GOOS:
// either the body of the branch or a later else branch, so Windows takes a
// different path.
func guarded(stack []ast.Node) bool {
	for i := len(stack) - 2; i >= 0; i-- {
		switch s := stack[i].(type) {
		case *ast.BlockStmt:
			// An earlier `if runtime.GOOS == "windows" { ...; return }` in
			// the same block sends Windows elsewhere.
			for _, st := range s.List {
				if st == stack[i+1] {
					break
				}
				if is, ok := st.(*ast.IfStmt); ok && mentionsGOOS(is.Cond) && endsInReturn(is.Body) {
					return true
				}
			}
		case *ast.IfStmt:
			if mentionsGOOS(s.Cond) && stack[i+1] != s.Cond {
				return true
			}
		case *ast.CaseClause:
			for _, e := range s.List {
				if mentionsGOOS(e) {
					return true
				}
			}
		case *ast.SwitchStmt:
			if s.Tag != nil && mentionsGOOS(s.Tag) {
				return true
			}
		case *ast.BinaryExpr:
			// runtime.GOOS == "windows" || ... short-circuits.
			if (s.Op == token.LOR || s.Op == token.LAND) && mentionsGOOS(s.X) && stack[i+1] == s.Y {
				return true
			}
		}
	}
	return false
}

func endsInReturn(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

func mentionsGOOS(e ast.Node) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "GOOS" && isIdent(sel.X, "runtime") {
			found = true
		}
		return !found
	})
	return found
}
