package durable

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func flushed(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReplaceAndCreateNew: on Windows every replace and create is a
// write-through MoveFileEx and no directory is opened (FR-21.23); on Linux
// and macOS the directory is synced after the rename.
func TestReplaceAndCreateNew(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Partial: the Policy Store, Server Registry and backup restore
		// paths are checked through this hook by their own tests.
		reqtest.Partial(t, "FR-21.23")
	}
	var mu sync.Mutex
	var ops []Op
	defer Observe(func(o Op) { mu.Lock(); ops = append(ops, o); mu.Unlock() })()

	dir := t.TempDir()
	dst := filepath.Join(dir, "control.json")
	flushed(t, dst, "old")
	tmp := filepath.Join(dir, ".control.json.tmp")
	flushed(t, tmp, "new")
	if err := Replace(tmp, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Fatalf("dst = %q", b)
	}
	rev := filepath.Join(dir, "rev")
	tmp2 := filepath.Join(dir, ".rev")
	flushed(t, tmp2, "r1")
	if err := CreateNew(tmp2, rev); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(tmp2)
	tmp3 := filepath.Join(dir, ".rev2")
	flushed(t, tmp3, "r2")
	if err := CreateNew(tmp3, rev); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateNew over an existing file: %v", err)
	}
	if b, _ := os.ReadFile(rev); string(b) != "r1" {
		t.Fatalf("existing file replaced: %q", b)
	}

	mu.Lock()
	defer mu.Unlock()
	var moves, syncs int
	for _, o := range ops {
		switch o.Kind {
		case "replace", "create":
			moves++
			if runtime.GOOS == "windows" && !o.WriteThrough {
				t.Errorf("%s %s without MOVEFILE_WRITE_THROUGH", o.Kind, o.Path)
			}
		case "syncdir":
			syncs++
		}
		if runtime.GOOS == "windows" && o.DirOpened {
			t.Errorf("%s opened directory %s on Windows", o.Kind, o.Path)
		}
	}
	if moves != 2 {
		t.Fatalf("ops = %+v", ops)
	}
	if runtime.GOOS != "windows" && syncs != 2 {
		t.Fatalf("directory not synced after each rename: %+v", ops)
	}
}
