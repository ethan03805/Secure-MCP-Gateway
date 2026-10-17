package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// rootfsDirs and rootfsFiles are created in the Gateway-built root
// directory. With a read-only root and a user namespace that does not map
// the Gateway's own UID, the runtime cannot create mount points itself, so
// every mount point exists in advance.
var (
	rootfsDirs  = []string{"proc", "dev", "sys", "tmp", "run", "var/tmp", "etc", strings.TrimPrefix(ServerBinDir, "/"), strings.TrimPrefix(WorkDir, "/")}
	rootfsFiles = []string{"etc/hosts", "etc/resolv.conf", "etc/hostname", "etc/passwd", "etc/group", "run/.containerenv"}
)

// PrepareRootfs makes dir an empty root filesystem with mount points for
// every mount of the launch specification. It is idempotent and safe to
// call for each launch. Nothing in it is writable by an instance: the
// container mounts it read-only.
func PrepareRootfs(dir string, mounts []Mount) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("root directory %q must be absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- instances (other UIDs) must traverse it
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- as above
		return err
	}
	for _, d := range rootfsDirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil { // #nosec G301 -- mount points
			return err
		}
	}
	for _, f := range rootfsFiles {
		if err := touch(filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	mtab := filepath.Join(dir, "etc", "mtab")
	if _, err := os.Lstat(mtab); errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink("/proc/mounts", mtab); err != nil {
			return err
		}
	}
	passwd := filepath.Join(dir, "etc", "passwd")
	if st, err := os.Stat(passwd); err == nil && st.Size() == 0 {
		// A user entry for the default instance user, so getpwuid works.
		if err := os.WriteFile(passwd, []byte("root:x:0:0::/:/nonexistent\nsmcp:x:1000:1000::/work:/nonexistent\n"), 0o644); err != nil { // #nosec G306 -- world-readable by design
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "etc", "group"), []byte("root:x:0:\nsmcp:x:1000:\n"), 0o644); err != nil { // #nosec G306 -- as above
			return err
		}
	}
	for _, m := range mounts {
		p := filepath.Join(dir, filepath.Clean("/"+m.Target))
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			return fmt.Errorf("mount target %q leaves the root directory", m.Target)
		}
		st, err := os.Stat(m.Source)
		if err != nil {
			return err
		}
		if st.IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil { // #nosec G301 -- mount point
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- mount point
			return err
		}
		if err := touch(p); err != nil {
			return err
		}
	}
	return nil
}

func touch(p string) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDONLY, 0o644) // #nosec G302 G304 -- mount point inside the Gateway root directory
	if err != nil {
		return err
	}
	return f.Close()
}
