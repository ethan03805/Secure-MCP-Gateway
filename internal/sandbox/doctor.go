package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Check statuses.
const (
	CheckPass = "pass"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Check is one enforced-profile prerequisite (SRS 1.5.1) as found on this
// host.
type Check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Remedy string `json:"remedy,omitempty"`
}

// DoctorOptions parameterize Doctor. Zero values inspect the running host.
type DoctorOptions struct {
	// Podman is the podman binary (default: PATH lookup).
	Podman string
	// CgroupManager is runtime.cgroup_manager; when set, `podman info`
	// runs with it, so the delegation check sees what containers will get.
	CgroupManager string
	// Root prefixes every host file read (tests).
	Root string
	// GOOS and GOARCH override the platform (tests).
	GOOS, GOARCH string
	// Euid overrides the effective UID (tests); nil reads it.
	Euid *int
	// User overrides the user name (tests).
	User string
	// Run executes a command and returns its standard output (tests).
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath overrides executable lookup (tests).
	LookPath func(string) (string, error)
	// SubIDMin is the smallest acceptable subordinate ID range (default
	// 65536, CP-46).
	SubIDMin int
}

// podmanInfo is the subset of `podman info --format json` the doctor reads.
type podmanInfo struct {
	Host struct {
		CgroupVersion     string   `json:"cgroupVersion"`
		CgroupManager     string   `json:"cgroupManager"`
		CgroupControllers []string `json:"cgroupControllers"`
		OCIRuntime        struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"ociRuntime"`
		Security struct {
			Rootless        bool `json:"rootless"`
			SeccompEnabled  bool `json:"seccompEnabled"`
			AppArmorEnabled bool `json:"apparmorEnabled"`
			SELinuxEnabled  bool `json:"selinuxEnabled"`
		} `json:"security"`
	} `json:"host"`
	Version struct {
		Version string `json:"Version"`
	} `json:"version"`
}

// MinKernel is the oldest kernel the enforced profile supports (SRS 1.5.1).
var MinKernel = [2]int{6, 8}

// Doctor checks every enforced-profile prerequisite and returns one Check
// per prerequisite, in a fixed order. It changes nothing on the host. It is
// the function behind `smcpctl runtime doctor` and is meant to be called by
// `smcpctl doctor` as well.
func Doctor(ctx context.Context, o DoctorOptions) []Check {
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	if o.Euid == nil {
		e := os.Geteuid()
		o.Euid = &e
	}
	if o.User == "" {
		if u, err := user.Current(); err == nil {
			o.User = u.Username
		}
	}
	if o.Run == nil {
		o.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- fixed diagnostic commands
		}
	}
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.SubIDMin == 0 {
		o.SubIDMin = 65536
	}
	read := func(p string) (string, error) {
		b, err := os.ReadFile(filepath.Join(o.Root, p)) // #nosec G304 -- fixed host paths
		return strings.TrimSpace(string(b)), err
	}
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(o.Root, p)); return err == nil }
	var out []Check
	add := func(id, name string, ok bool, detail, remedy string) {
		c := Check{ID: id, Name: name, Status: CheckPass, Detail: detail}
		if !ok {
			c.Status, c.Remedy = CheckFail, remedy
		}
		out = append(out, c)
	}

	add("os", "Linux", o.GOOS == "linux", o.GOOS, "the enforced profile runs on Linux only; use profile.mode = \"standalone\" on this host")
	add("arch", "x86_64 or arm64", o.GOARCH == "amd64" || o.GOARCH == "arm64", o.GOARCH, "use an x86_64 or arm64 host")
	if o.GOOS != "linux" {
		return out
	}
	rel, err := read("/proc/sys/kernel/osrelease")
	add("kernel", fmt.Sprintf("kernel %d.%d or later", MinKernel[0], MinKernel[1]), err == nil && kernelAtLeast(rel, MinKernel), rel,
		"upgrade the kernel (Ubuntu 24.04 ships 6.8)")
	add("rootless", "Gateway runs as a non-root user", *o.Euid != 0, "euid "+strconv.Itoa(*o.Euid),
		"run smcpd as the smcp-core service identity, not root (packaging/linux/install-enforced.sh creates it)")
	add("cgroup-v2", "cgroup v2 unified hierarchy", exists("/sys/fs/cgroup/cgroup.controllers"), "",
		"boot with systemd.unified_cgroup_hierarchy=1")
	userns := true
	detail := ""
	if v, err := read("/proc/sys/user/max_user_namespaces"); err == nil {
		detail = "max_user_namespaces=" + v
		if n, _ := strconv.Atoi(v); n == 0 {
			userns = false
		}
	}
	if v, err := read("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && v == "0" {
		userns, detail = false, detail+" unprivileged_userns_clone=0"
	}
	add("userns", "unprivileged user namespaces", userns, strings.TrimSpace(detail), "sysctl -w user.max_user_namespaces=28633 kernel.unprivileged_userns_clone=1")
	if v, err := read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && v == "1" {
		out = append(out, Check{ID: "userns-apparmor", Name: "AppArmor user-namespace restriction", Status: CheckWarn,
			Detail: "kernel.apparmor_restrict_unprivileged_userns=1",
			Remedy: "Podman needs an AppArmor profile that permits user namespaces; if the podman check below fails, see docs/sandbox.md"})
	}
	for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
		size := subIDRange(read, f, o.User, strconv.Itoa(*o.Euid))
		add("subid-"+filepath.Base(f), fmt.Sprintf("%s range of %d or more for %s", f, o.SubIDMin, o.User), size >= o.SubIDMin,
			fmt.Sprintf("%d IDs", size), fmt.Sprintf("usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s", o.User))
	}
	_, e1 := o.LookPath("newuidmap")
	_, e2 := o.LookPath("newgidmap")
	add("uidmap", "newuidmap and newgidmap", e1 == nil && e2 == nil, "", "apt-get install uidmap")
	_, err = o.LookPath("nft")
	add("nftables", "nftables (nft)", err == nil, "", "apt-get install nftables")
	add("systemd", "systemd", exists("/run/systemd/system"), "", "the enforced profile needs systemd as the service manager")
	lsm := ""
	if exists("/sys/kernel/security/apparmor") {
		lsm = "apparmor"
	} else if exists("/sys/fs/selinux/enforce") {
		lsm = "selinux"
	}
	add("lsm", "AppArmor or SELinux", lsm != "", lsm, "enable AppArmor (Ubuntu, Debian) or SELinux (Fedora, RHEL)")

	pod := o.Podman
	if pod == "" {
		if p, err := o.LookPath("podman"); err == nil {
			pod = p
		}
	}
	if pod == "" {
		add("podman", "Podman", false, "not found", "apt-get install podman crun")
		return out
	}
	infoArgs := []string{"info", "--format", "json"}
	if o.CgroupManager != "" {
		infoArgs = append([]string{"--cgroup-manager=" + o.CgroupManager}, infoArgs...)
	}
	raw, err := o.Run(ctx, pod, infoArgs...)
	var info podmanInfo
	if err == nil {
		err = json.Unmarshal(raw, &info)
	}
	add("podman", "Podman responds (podman info)", err == nil, info.Version.Version, "run `podman info` as this user and fix what it reports")
	if err != nil {
		return out
	}
	h := info.Host
	add("podman-rootless", "Podman runs rootless", h.Security.Rootless, "", "run smcpd as a non-root user")
	add("crun", "OCI runtime crun", h.OCIRuntime.Name == "crun", h.OCIRuntime.Name, "apt-get install crun; set runtime = \"crun\" in containers.conf")
	add("podman-cgroup-v2", "Podman uses cgroup v2", h.CgroupVersion == "v2", h.CgroupVersion+" "+h.CgroupManager, "boot with the unified cgroup hierarchy")
	var missing []string
	for _, c := range []string{"memory", "pids", "cpu"} {
		if !slices.Contains(h.CgroupControllers, c) {
			missing = append(missing, c)
		}
	}
	add("cgroup-delegation", "memory, pids and cpu controllers delegated to this user", len(missing) == 0,
		strings.Join(h.CgroupControllers, ","), "systemd delegates them to user@.service by default; check /etc/systemd/system/user@.service.d (missing: "+strings.Join(missing, ",")+")")
	add("seccomp", "seccomp available to Podman", h.Security.SeccompEnabled, "", "install a kernel with seccomp and the containers-common seccomp profile")
	return out
}

// Failed returns the checks that did not pass (warnings excluded).
func Failed(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if c.Status == CheckFail {
			out = append(out, c)
		}
	}
	return out
}

func kernelAtLeast(rel string, min [2]int) bool {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	mn, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > min[0] || (maj == min[0] && mn >= min[1])
}

// subIDRange returns the total subordinate IDs of name in an /etc/subuid
// style file.
func subIDRange(read func(string) (string, error), file, name, uid string) int {
	s, err := read(file)
	if err != nil {
		return 0
	}
	total := 0
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(f) == 3 && (f[0] == name || f[0] == uid) {
			if n, err := strconv.Atoi(f[2]); err == nil {
				total += n
			}
		}
	}
	return total
}
