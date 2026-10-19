package app

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// RuntimeLimits returns the per-instance resource limits of the
// SubprocessLauncher (applied on Windows through the instance's Job Object,
// FR-21.12): a [[runtime.server]] value first, then the limit the verified
// manifest declares, then the [runtime] value, which defaults to CP-24.
func RuntimeLimits(rt config.Runtime) func(pipeline.ServerSpec) pipeline.ResourceLimits {
	return func(spec pipeline.ServerSpec) pipeline.ResourceLimits {
		srv := rt.FindServer(spec.Alias)
		return pipeline.ResourceLimits{
			MemoryBytes: firstPositive(srv.MemoryBytes, spec.Limits.MemoryBytes, rt.MemoryBytes),
			CPUs:        firstPositive(srv.CPUs, spec.Limits.CPUs, rt.CPUs),
			Processes:   firstPositive(srv.Pids, spec.Limits.Processes, rt.Pids),
		}
	}
}

func firstPositive[T int | int64 | float64](v ...T) T {
	for _, x := range v {
		if x > 0 {
			return x
		}
	}
	return 0
}
