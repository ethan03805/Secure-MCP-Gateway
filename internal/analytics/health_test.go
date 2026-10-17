package analytics

import (
	"errors"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestObservationHealthCheck: an enabled service whose store failed to
// open makes the Gateway degraded, never fail-closed.
func TestObservationHealthCheck(t *testing.T) {
	reqtest.Partial(t, "FR-7.12")
	var off *Service
	if c := off.HealthCheck()(time.Now()); len(c) != 0 || off.StoreError() != nil {
		t.Fatalf("nil service: %v", c)
	}
	s := &Service{S: Settings{Enabled: true}}
	if c := s.HealthCheck()(time.Now()); len(c) != 0 {
		t.Fatalf("healthy store: %v", c)
	}
	s.storeErr = errors.New("duckdb: disk full")
	c := s.HealthCheck()(time.Now())
	if len(c) != 1 || c[0].Name != health.CauseObservationUnavailable || c[0].Critical || s.StoreError() == nil {
		t.Fatalf("%+v", c)
	}
	mon := health.New(health.Options{Log: diag.Discard()})
	mon.Register("observation", s.HealthCheck())
	mon.Evaluate()
	if mon.State() != health.Degraded || len(mon.Gate()) != 0 {
		t.Fatalf("state %s gate %v", mon.State(), mon.Gate())
	}
}
