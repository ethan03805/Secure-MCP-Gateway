package pipeline

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// InProcessLauncher runs MCP servers built in this process, connected over
// pipes, for tests and for elements that embed a server. Servers maps the
// ServerSpec.Command to a constructor. It provides no confinement unless
// Confine is set (tests of the enforced profile).
type InProcessLauncher struct {
	Servers map[string]func() *mcp.Server
	Confine bool
}

// Name implements Launcher.
func (InProcessLauncher) Name() string { return "in-process" }

// Confined implements Launcher.
func (l InProcessLauncher) Confined() bool { return l.Confine }

// Launch implements Launcher.
func (l InProcessLauncher) Launch(_ context.Context, spec ServerSpec) (Process, error) {
	build := l.Servers[spec.Command]
	if build == nil {
		return nil, fmt.Errorf("no in-process server for %q", spec.Command)
	}
	toSrvR, toSrvW := io.Pipe()
	fromSrvR, fromSrvW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &inProcess{Reader: fromSrvR, Writer: toSrvW, cancel: cancel, pipes: []io.Closer{toSrvW, toSrvR, fromSrvR, fromSrvW}, done: make(chan struct{})}
	srv := build()
	go func() {
		defer close(p.done)
		_ = srv.Run(ctx, &mcp.IOTransport{Reader: toSrvR, Writer: fromSrvW})
	}()
	return p, nil
}

type inProcess struct {
	io.Reader
	io.Writer
	cancel context.CancelFunc
	pipes  []io.Closer
	done   chan struct{}
	once   sync.Once
}

func (p *inProcess) Close() error {
	p.once.Do(func() {
		for _, c := range p.pipes {
			c.Close()
		}
		p.cancel()
		<-p.done
	})
	return nil
}

func (p *inProcess) Stderr() string { return "" }
