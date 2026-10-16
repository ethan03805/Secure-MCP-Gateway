package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T, root string) *mcp.ClientSession {
	t.Helper()
	srv, closeRoot, err := newServer(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeRoot)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go srv.Run(ctx, st)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(*mcp.TextContent).Text, res.IsError
}

func TestReferenceServerTools(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	os.Symlink(outside, filepath.Join(dir, "escape.txt"))
	os.WriteFile(filepath.Join(dir, "big.txt"), []byte(strings.Repeat("x", maxRead+1)), 0o644)

	cs := connect(t, dir)
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(lt.Tools) != 4 {
		t.Fatalf("%v %v", lt, err)
	}
	for _, tool := range lt.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s not marked read-only", tool.Name)
		}
	}
	if out, _ := call(t, cs, "echo", map[string]any{"text": "hi"}); out != "hi" {
		t.Fatal(out)
	}
	if out, isErr := call(t, cs, "list_files", map[string]any{"path": ""}); isErr || !strings.Contains(out, "hello.txt") || !strings.Contains(out, "sub/") {
		t.Fatal(out)
	}
	if out, isErr := call(t, cs, "read_file", map[string]any{"path": "hello.txt"}); isErr || out != "hello world" {
		t.Fatal(out)
	}
	for _, p := range []string{"../secret.txt", "/etc/passwd", "escape.txt", "big.txt", "sub"} {
		if out, isErr := call(t, cs, "read_file", map[string]any{"path": p}); !isErr || strings.Contains(out, "secret") && !strings.Contains(out, "cannot") {
			t.Errorf("%s: %q %v", p, out, isErr)
		}
	}
	// Without a root only echo and time_now exist.
	cs2 := connect(t, "")
	lt, _ = cs2.ListTools(context.Background(), nil)
	if len(lt.Tools) != 2 {
		t.Fatalf("%d tools without root", len(lt.Tools))
	}
}
