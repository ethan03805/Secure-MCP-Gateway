//go:build !windows

package main

import (
	"context"
	"log/slog"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
)

// platformRun runs the Gateway until SIGINT or SIGTERM.
func platformRun(cfgPath, level string) error { return run(context.Background(), cfgPath, level) }

// watchConsoleClose does nothing off Windows.
func watchConsoleClose(*app.App, *slog.Logger) {}
