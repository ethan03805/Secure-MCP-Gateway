package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
)

// contextforgeChoice is the setup question of FR-22.44: the default is
// not to enable the bundled instance, with one line on what it adds and
// one on its risk.
const contextforgeChoice = `
Bundled ContextForge instance (optional)
  Adds: hosted servers from the IBM ContextForge catalog, reached only through the Gateway.
  Risk: a large third-party service runs on this host, and the code of hosted servers cannot be inspected.
Enable it? [y/N]: `

// askContextForge asks the FR-22.44 question and reports a yes.
func askContextForge(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, contextforgeChoice)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// contextforgeConfig is the [contextforge] table bootstrap writes
// (FR-22.22): the operator's answer, false unless they chose it.
func contextforgeConfig(bundled bool) string {
	return fmt.Sprintf(`
# Bundled ContextForge instance (E-36, docs/contextforge.md), chosen at
# setup. While false, hosted catalog entries are refused and no
# ContextForge image is fetched. It also needs a [secrets] table.
[contextforge]
bundled = %t
`, bundled)
}

// pullImage fetches an image with the container engine; tests replace it.
var pullImage = func(ctx context.Context, eng bundle.Engine, ref string) error {
	out, err := exec.CommandContext(ctx, eng.Path, "pull", ref).CombinedOutput() //nolint:gosec // G204: engine from PATH, digest-pinned reference from the release lock
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fetchContextForge fetches the image of the release lock for this
// machine's Linux platform when a container engine is installed. A failure
// is reported, not fatal: `smcpctl contextforge start` fetches and
// verifies the image before the first start.
func fetchContextForge(out io.Writer) {
	lock := contextforge.ReleaseLock().ContextForge
	ref := lock.ImageRef("linux/" + runtime.GOARCH)
	eng, err := bundle.FindEngine()
	if err != nil {
		fmt.Fprintf(out, "ContextForge image not fetched: %v. Install Podman or Docker; the image is fetched and verified at the first start.\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := pullImage(ctx, eng, ref); err != nil {
		fmt.Fprintf(out, "ContextForge image not fetched (%v); it is fetched and verified at the first start.\n", err)
		return
	}
	fmt.Fprintf(out, "fetched ContextForge %s (%s)\n", lock.Version, ref)
}
