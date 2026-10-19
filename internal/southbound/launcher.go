package southbound

import (
	"context"
	"net/http"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Wrap returns a Launcher that connects to a ServerSpec with a URL over
// Streamable HTTP and hands every other spec to inner (a nil inner is the
// unconfined SubprocessLauncher). Name and Confined are inner's: an HTTP
// server is never inside the Gateway's sandbox, and the dispatcher refuses
// high-risk server classes for it in every profile. It is the innermost
// wrapper, so the Secret Broker's teardown and the package checks apply to
// HTTP instances as to launched ones. When inner is pipeline.EgressAware,
// so is the wrapper.
//
// The bearer token comes from the spec's environment: TokenEnv (S4) or the
// file TokenFileEnv names (S2, S3), as the Secret Broker delivers them.
func Wrap(inner pipeline.Launcher) pipeline.Launcher {
	if inner == nil {
		inner = pipeline.SubprocessLauncher{}
	}
	l := &Launcher{Inner: inner}
	if ea, ok := inner.(pipeline.EgressAware); ok {
		return &egressAware{Launcher: l, ea: ea}
	}
	return l
}

// Launcher is the wrapper Wrap returns.
type Launcher struct {
	Inner pipeline.Launcher
	// HTTP replaces the transport's client (tests).
	HTTP *http.Client
}

type egressAware struct {
	*Launcher
	ea pipeline.EgressAware
}

func (l *egressAware) SetEgress(a pipeline.EgressAttacher) { l.ea.SetEgress(a) }

// Name implements pipeline.Launcher.
func (l *Launcher) Name() string { return l.Inner.Name() }

// Confined implements pipeline.Launcher.
func (l *Launcher) Confined() bool { return l.Inner.Confined() }

// Launch implements pipeline.Launcher.
func (l *Launcher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	if spec.URL == "" {
		return l.Inner.Launch(ctx, spec)
	}
	tok, err := TokenFromEnv(func(k string) string { return spec.Env[k] })
	if err != nil {
		return nil, err
	}
	return Dial(Endpoint{URL: spec.URL, Token: tok, CAFile: spec.CAFile, MaxMessageBytes: spec.MaxMessageBytes, HTTP: l.HTTP})
}
