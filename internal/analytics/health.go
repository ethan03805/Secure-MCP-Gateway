package analytics

import (
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
)

// HealthCheck reports the non-critical cause observation_store_unavailable
// while observation is enabled but its store could not be opened (records
// are then counted and dropped). The Gateway is degraded; observation never
// gates enforcement. A disabled service reports nothing.
func (s *Service) HealthCheck() health.Check {
	return func(time.Time) []health.Cause {
		if s.Disabled() || s.storeErr == nil {
			return nil
		}
		return []health.Cause{{Name: health.CauseObservationUnavailable, Detail: "observation store unavailable: " + s.storeErr.Error()}}
	}
}

// StoreError returns why the store could not be opened, or nil.
func (s *Service) StoreError() error {
	if s.Disabled() {
		return nil
	}
	return s.storeErr
}
