package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Upgrade support of the bundled instance (SRS FR-22.31): the Connector
// stops the instance, backs up D-16, switches the artifact (image or
// virtual environment) to the new release and starts it; on any failure
// it restores D-16 and switches back.

// SetImage switches the container to another digest-pinned image for the
// next start.
func (i *Instance) SetImage(ref string) error {
	if !strings.Contains(ref, "@sha256:") {
		return fmt.Errorf("bundle: image %q is not pinned by digest", ref)
	}
	i.mu.Lock()
	i.o.Image, i.st.Image = ref, ref
	i.mu.Unlock()
	return nil
}

// Image is the image of the next start.
func (i *Instance) Image() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.o.Image
}

func (i *Instance) backupVolume() string { return i.o.Name + "-backup" }

// copyVolume copies the files of volume src into a new, empty volume dst
// with the given image's cp, ownership and modes kept. Nothing else runs
// in that container: no network, all capabilities dropped except those cp
// needs to keep owners and read every file.
func (i *Instance) copyVolume(ctx context.Context, image, src, dst string) error {
	_, _ = i.engine(ctx, nil, "volume", "rm", "-f", dst)
	if out, err := i.engine(ctx, nil, "volume", "create", dst); err != nil {
		return fmt.Errorf("create volume %s: %w: %s", dst, err, out)
	}
	out, err := i.engine(ctx, nil, "run", "--rm", "--network=none", "--user", "0", "--cap-drop", "ALL",
		"--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges",
		"--label", "smcp.component=contextforge", "--entrypoint", "/bin/cp",
		"-v", src+":/src:ro", "-v", dst+":/dst", image, "-a", "/src/.", "/dst/")
	if err != nil {
		return fmt.Errorf("copy volume %s to %s: %w: %s", src, dst, err, out)
	}
	return nil
}

// BackupData copies D-16 into the backup volume. The instance must be
// stopped.
func (i *Instance) BackupData(ctx context.Context) error {
	if _, err := i.engine(ctx, nil, "volume", "inspect", i.volume()); err != nil {
		// Never started: an empty backup restores an empty D-16.
		_, _ = i.engine(ctx, nil, "volume", "rm", "-f", i.backupVolume())
		out, err := i.engine(ctx, nil, "volume", "create", i.backupVolume())
		if err != nil {
			return fmt.Errorf("create volume %s: %w: %s", i.backupVolume(), err, out)
		}
		return nil
	}
	return i.copyVolume(ctx, i.Image(), i.volume(), i.backupVolume())
}

// RestoreData replaces D-16 with the backup. The instance must be
// stopped.
func (i *Instance) RestoreData(ctx context.Context) error {
	if out, err := i.engine(ctx, nil, "volume", "rm", "-f", i.volume()); err != nil {
		return fmt.Errorf("remove volume: %w: %s", err, out)
	}
	return i.copyVolume(ctx, i.Image(), i.backupVolume(), i.volume())
}

// DropBackup removes the backup volume.
func (i *Instance) DropBackup(ctx context.Context) error {
	out, err := i.engine(ctx, nil, "volume", "rm", "-f", i.backupVolume())
	if err != nil {
		return fmt.Errorf("remove volume %s: %w: %s", i.backupVolume(), err, out)
	}
	return nil
}

// RemoveImageRef removes an image no longer in use (the previous release
// after an upgrade).
func (i *Instance) RemoveImageRef(ctx context.Context, ref string) error {
	out, err := i.engine(ctx, nil, "rmi", ref)
	if err != nil && !strings.Contains(strings.ToLower(out), "no such image") {
		return fmt.Errorf("remove image: %w: %s", err, out)
	}
	return nil
}

// SetPython switches the managed process to another interpreter (the
// virtual environment of another release) for the next start.
func (p *Process) SetPython(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("bundle: interpreter %q is not an absolute path", path)
	}
	p.mu.Lock()
	p.o.Python = path
	p.mu.Unlock()
	return nil
}

// Python is the interpreter of the next start.
func (p *Process) Python() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.o.Python
}

func (p *Process) dataDir() string   { return filepath.Join(p.o.Dir, "data") }
func (p *Process) backupDir() string { return filepath.Join(p.o.Dir, "data.backup") }

// BackupData copies D-16 into data.backup. The process must be stopped.
func (p *Process) BackupData(context.Context) error {
	if err := os.RemoveAll(p.backupDir()); err != nil {
		return err
	}
	if _, err := os.Stat(p.dataDir()); errors.Is(err, fs.ErrNotExist) {
		return os.MkdirAll(p.backupDir(), 0o700)
	}
	return copyTree(p.dataDir(), p.backupDir())
}

// RestoreData replaces D-16 with data.backup. The process must be stopped.
func (p *Process) RestoreData(context.Context) error {
	if err := os.RemoveAll(p.dataDir()); err != nil {
		return err
	}
	return copyTree(p.backupDir(), p.dataDir())
}

// DropBackup removes data.backup.
func (p *Process) DropBackup(context.Context) error { return os.RemoveAll(p.backupDir()) }

// RemoveImageRef implements the Connector's Upgradable: the previous
// release's virtual environment is the directory of interpreter ref.
func (p *Process) RemoveImageRef(_ context.Context, ref string) error {
	venv := filepath.Dir(filepath.Dir(ref))
	if !strings.HasPrefix(filepath.Base(venv), "venv-") || filepath.Dir(venv) != p.o.Dir {
		return fmt.Errorf("bundle: %s is not a virtual environment of the instance", ref)
	}
	return os.RemoveAll(venv)
}

// copyTree copies the regular files and directories under src into dst
// with their modes; symbolic links and other files are refused.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(to, info.Mode().Perm()|0o700)
		case d.Type().IsRegular():
			return copyFile(path, to, info.Mode().Perm())
		}
		return fmt.Errorf("bundle: %s is not a regular file or directory", path)
	})
}

func copyFile(from, to string, mode fs.FileMode) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
