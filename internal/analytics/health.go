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
		if s.Disabled() {
			return nil
		}
		var out []health.Cause
		if s.storeErr != nil {
			out = append(out, health.Cause{Name: health.CauseObservationUnavailable, Detail: "observation store unavailable: " + s.storeErr.Error()})
		}
		// FR-9.12: the degradation stage is reported to the Health &
		// Safety Monitor; observation never gates enforcement.
		if st := s.degrade.Stage(); st > StageNormal {
			out = append(out, health.Cause{Name: CauseObservationDegraded, Detail: "observation degraded to stage " + StageNames[st] + ": " + s.degrade.Reason()})
		}
		return out
	}
}

// StorageQuota returns the Observation Store's quota for the Health &
// Safety Monitor (FR-9.15), or nil when observation is disabled.
func (s *Service) StorageQuota() *health.Quota {
	if s.Disabled() {
		return nil
	}
	return &health.Quota{Name: "observation_store", Dir: s.S.Dir, Limit: s.S.StorageQuota}
}

// CauseObservationDegraded is the non-critical health cause while the
// observation path is degraded (FR-9.12).
const CauseObservationDegraded = "observation_degraded"

// Degradation returns the current degradation stage and its name.
func (s *Service) Degradation() (int, string) {
	if s.Disabled() {
		return StageNormal, StageNames[StageNormal]
	}
	st := s.degrade.Stage()
	return st, StageNames[st]
}

// StoreError returns why the store could not be opened, or nil.
func (s *Service) StoreError() error {
	if s.Disabled() {
		return nil
	}
	return s.storeErr
}
