package connector

import (
	"context"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// recordingLauncher keeps the specs it is asked to launch.
type recordingLauncher struct {
	specs []pipeline.ServerSpec
}

func (r *recordingLauncher) Name() string   { return "recording" }
func (r *recordingLauncher) Confined() bool { return false }

func (r *recordingLauncher) Launch(_ context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	r.specs = append(r.specs, spec)
	return nil, nil
}

type egressLauncher struct {
	recordingLauncher
	set pipeline.EgressAttacher
}

func (e *egressLauncher) SetEgress(a pipeline.EgressAttacher) { e.set = a }

type nopAttacher struct{}

func (nopAttacher) Attach(context.Context, pipeline.EgressRequest) (*pipeline.EgressAttachment, error) {
	return nil, nil
}

// TestWrapLauncherPassThrough: a connection that is not a registered hosted
// package reaches the inner launcher unchanged and gets no token, whether
// there is no Connector, no bundled instance, or an unrelated URL; the
// wrapper keeps the inner launcher's egress handling.
func TestWrapLauncherPassThrough(t *testing.T) {
	inner := &recordingLauncher{}
	var c *Connector
	l := WrapLauncher(inner, func() *Connector { return c })
	spec := pipeline.ServerSpec{Alias: "a", URL: "https://example.com/mcp", Env: map[string]string{"K": "v"}}
	if _, err := l.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	c = &Connector{hosted: map[string]*hostedPkg{}, reconcileReq: make(chan struct{}, 1)}
	if _, err := l.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if len(inner.specs) != 2 {
		t.Fatalf("launched %d", len(inner.specs))
	}
	for _, s := range inner.specs {
		if len(s.Env) != 1 || s.Env["K"] != "v" || s.URL != spec.URL {
			t.Fatalf("spec changed: %+v", s)
		}
	}
	if _, ok := l.(pipeline.EgressAware); ok {
		t.Fatal("a launcher without egress handling gained it")
	}

	el := &egressLauncher{}
	w := WrapLauncher(el, func() *Connector { return nil })
	ea, ok := w.(pipeline.EgressAware)
	if !ok {
		t.Fatal("egress handling lost")
	}
	ea.SetEgress(nopAttacher{})
	if el.set == nil {
		t.Fatal("SetEgress not passed on")
	}

	// ReconcileNow never blocks, however often it is asked.
	for range 3 {
		c.ReconcileNow()
	}
	if len(c.reconcileReq) != 1 {
		t.Fatalf("pending requests %d", len(c.reconcileReq))
	}
}
