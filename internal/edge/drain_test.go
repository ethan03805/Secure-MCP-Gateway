package edge

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDrainStopReleasesInFlightResults covers the drain of SR-7.7-1: a
// stop entered with StopDraining refuses new calls but lets a call in
// flight release its result; an emergency Stop during the drain ends the
// call, and ResumeDraining does not lift that stop.
func TestDrainStopReleasesInFlightResults(t *testing.T) {
	reqtest.Partial(t, "SR-7.7-1")
	started := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	h := newHarness(t, harnessOpts{backend: gatedBackend(started, release)})
	_, tok := h.session("ro")
	cs := h.client(tok)
	call := func() chan error {
		t.Helper()
		errc := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{}})
			errc <- err
		}()
		select {
		case <-started:
		case err := <-errc:
			t.Fatalf("call ended before reaching the backend: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("call never reached the backend")
		}
		return errc
	}
	recv := func(errc chan error) error {
		t.Helper()
		select {
		case err := <-errc:
			return err
		case <-time.After(30 * time.Second):
			t.Fatal("call did not end")
			return nil
		}
	}

	errc := call()
	if err := h.gw.StopDraining("backup", "backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "x"}}); err == nil {
		t.Fatal("a new call ran during the drain")
	}
	release <- struct{}{}
	if err := recv(errc); err != nil {
		t.Fatalf("drained call: %v", err)
	}
	if err := h.gw.ResumeDraining("backup"); err != nil {
		t.Fatal(err)
	}
	if h.gw.Stopped() {
		t.Fatal("still stopped after ResumeDraining")
	}

	errc = call()
	if err := h.gw.StopDraining("backup", "backup"); err != nil {
		t.Fatal(err)
	}
	if err := h.gw.Stop("operator", "drill"); err != nil {
		t.Fatal(err)
	}
	if err := recv(errc); err == nil {
		t.Fatal("a call delivered its result under an emergency stop")
	}
	if err := h.gw.ResumeDraining("backup"); err != nil {
		t.Fatal(err)
	}
	if !h.gw.Stopped() {
		t.Fatal("ResumeDraining lifted an emergency stop")
	}
	if err := h.gw.Resume("operator"); err != nil {
		t.Fatal(err)
	}
	if h.gw.Stopped() {
		t.Fatal("still stopped after Resume")
	}
}
