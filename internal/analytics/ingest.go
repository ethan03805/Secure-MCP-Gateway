package analytics

import "github.com/ethan03805/secure-mcp-gateway/internal/obsstore"

// IngestStats are the store writer's counters: what FR-11.6 checks after a
// replay.
type IngestStats struct {
	// Written is the number of rows the store accepted.
	Written int64 `json:"written"`
	// PressureOffers counts offers made while the writer's queue was at
	// 80% or more of its capacity: the backpressure signal of FR-9.6.
	PressureOffers uint64 `json:"pressureOffers"`
	// Drops are the rows dropped by the writer, by reason (a full queue or
	// a failed store write).
	Drops map[string]uint64 `json:"drops"`
	// LastError is the error of the most recent batch write, "" after a
	// success.
	LastError string `json:"lastError,omitempty"`
}

// Offer queues one row for table through the store writer, exactly as the
// collector's records are queued (writeRecord): it never blocks, and a full
// queue drops the row and counts it. The reference workload uses it to
// replay observation records at a fixed rate (FR-11.6). It reports false
// when the service has no store writer.
func (s *Service) Offer(table string, r obsstore.Row) bool {
	if s.Disabled() || s.writer == nil {
		return false
	}
	s.writer.offer(table, r)
	return true
}

// IngestStats returns the store writer's counters (zero without a writer).
func (s *Service) IngestStats() IngestStats {
	if s.Disabled() || s.writer == nil {
		return IngestStats{Drops: map[string]uint64{}}
	}
	return IngestStats{Written: s.writer.written.Load(), PressureOffers: s.writer.pressure.Load(), Drops: s.writer.drops(), LastError: s.writer.lastError()}
}
