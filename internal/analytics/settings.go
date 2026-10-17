package analytics

import (
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
)

// Settings is the resolved Observation Policy: the [observation] table with
// defaults applied and every parameter name checked against the catalog.
type Settings struct {
	Enabled          bool
	Store            string
	Dir              string
	ExportDir        string
	KeyDir           string
	PolicyID         string
	Parameters       []string
	Escalation       []string
	SamplingRate     float64
	Retention        time.Duration
	Queue            int
	FlushRecords     int
	FlushInterval    time.Duration
	MetricsInterval  time.Duration
	MemoryLimit      int64
	Scoring          string
	RequireApproval  string
	Withhold         string
	Baseline         baseline.Config
	SnapshotInterval time.Duration
	SnapshotRecords  int64
	Auto             baseline.AutoLimits
	Thresholds       anomaly.Thresholds
}

// DefaultFeatures are the baselined features when none are configured.
var DefaultFeatures = []config.ObservationFeature{
	{Parameter: "request_bytes", Transform: "log1p"},
	{Parameter: "argument_count"},
	{Parameter: "argument_entropy"},
	{Parameter: "response_bytes", Transform: "log1p"},
	{Parameter: "response_entropy"},
	{Parameter: "server_execution_time", Transform: "log1p"},
	{Parameter: "inter_call_interval", Transform: "log1p"},
	{Parameter: "transition_surprise"},
	{Parameter: "calls_per_minute_session"},
}

func dur(d config.Duration, def time.Duration) time.Duration {
	if d.Duration > 0 {
		return d.Duration
	}
	return def
}

func resolve(dir, p, def string) string {
	if p == "" {
		return def
	}
	if filepath.IsAbs(p) || dir == "" {
		return p
	}
	return filepath.Join(dir, p)
}

// defaultFloor is the σ floor of a feature without one: 0.5 for an
// untransformed integer parameter (counts), 0.01 otherwise (transformed or
// real-valued features). The catalog does not yet carry floors.
func defaultFloor(p observe.Param, tr baseline.Transform) float64 {
	if p.DataType == "integer" && tr.Kind == "none" {
		return 0.5
	}
	return 0.01
}

// Resolve applies the defaults of docs/observation.md.
func Resolve(cfg *config.Config, cat *observe.Catalog) (Settings, error) {
	o := cfg.Observation
	s := Settings{Enabled: o.Enabled == nil || *o.Enabled, Store: o.Store, PolicyID: o.PolicyID, Queue: o.Queue,
		FlushRecords: o.FlushRecords, MemoryLimit: o.MemoryLimitBytes, Scoring: o.Scoring,
		RequireApproval: o.RequireApprovalBand, Withhold: o.WithholdBand}
	if s.Store == "" {
		s.Store = "auto"
	}
	s.Dir = resolve(cfg.Dir, o.Dir, filepath.Join(cfg.State.Dir, "observation"))
	s.ExportDir = resolve(cfg.Dir, o.ExportDir, filepath.Join(cfg.State.Dir, "exports"))
	s.KeyDir = filepath.Join(cfg.State.Dir, "keys", "research")
	if s.PolicyID == "" {
		s.PolicyID = "default"
	}
	var err error
	if len(o.Parameters) == 0 {
		s.Parameters = cat.DefaultParameters()
	} else if s.Parameters, err = cat.Resolve(o.Parameters); err != nil {
		return s, fmt.Errorf("observation.parameters: %w", err)
	}
	if s.Escalation, err = cat.Resolve(o.EscalationParameters); err != nil {
		return s, fmt.Errorf("observation.escalation_parameters: %w", err)
	}
	for _, n := range append(slices.Clone(s.Parameters), s.Escalation...) {
		p, _ := cat.Lookup(n)
		if p.CapturePoint == "periodic" {
			return s, fmt.Errorf("observation.parameters: %s is a periodic meta-metric, not a per-call parameter", p.ID)
		}
		if p.Sensitivity == "S3" {
			return s, fmt.Errorf("observation.parameters: %s is an S3 raw payload; raw payload capture is not available in this release", p.ID)
		}
	}
	s.SamplingRate = 0.1 // CP-31
	if o.SamplingRate != nil {
		s.SamplingRate = *o.SamplingRate
	}
	s.Retention = dur(o.Retention, 90*24*time.Hour) // CP-25
	if s.Queue == 0 {
		s.Queue = 4096
	}
	if s.FlushRecords == 0 {
		s.FlushRecords = 1000
	}
	s.FlushInterval = dur(o.FlushInterval, 200*time.Millisecond)
	s.MetricsInterval = dur(o.MetricsInterval, 10*time.Second)
	if s.MemoryLimit == 0 {
		s.MemoryLimit = 512 << 20 // CP-33
	}
	if s.Scoring == "" {
		s.Scoring = "async"
	}
	if s.RequireApproval == "" {
		s.RequireApproval = "off"
	}
	if s.Withhold == "" {
		s.Withhold = "off"
	}
	if (s.RequireApproval != "off" || s.Withhold != "off") && s.Scoring != "sync" {
		return s, fmt.Errorf("observation: require_approval_band and withhold_band need scoring = \"sync\"")
	}

	b := o.Baseline
	bc := baseline.Config{Dimensions: b.Contexts, NMin: b.NMin, HalfLife: b.HalfLife.Duration, Window: dur(b.LearningWindow, 30*24*time.Hour)}
	if len(bc.Dimensions) == 0 {
		bc.Dimensions = []string{"principal", "tool"}
	}
	feats := b.Features
	if len(feats) == 0 {
		feats = DefaultFeatures
	}
	for _, f := range feats {
		p, ok := cat.Lookup(f.Parameter)
		if !ok {
			return s, fmt.Errorf("observation.baseline.feature: unknown parameter %q", f.Parameter)
		}
		kind := f.Kind
		if kind == "" {
			kind = "numeric"
		}
		if kind == "numeric" && !p.Numeric() {
			return s, fmt.Errorf("observation.baseline.feature: %s (%s) is not numeric; use kind = \"categorical\"", p.ID, p.Name)
		}
		if p.CapturePoint == "periodic" || p.Sensitivity == "S3" {
			return s, fmt.Errorf("observation.baseline.feature: %s cannot be baselined per call", p.ID)
		}
		tr, err := baseline.ParseTransform(f.Transform)
		if err != nil {
			return s, fmt.Errorf("observation.baseline.feature %s: %w", p.ID, err)
		}
		floor := defaultFloor(p, tr)
		if f.SigmaFloor != nil {
			floor = *f.SigmaFloor
		}
		bc.Features = append(bc.Features, baseline.FeatureSpec{Name: p.Name, Kind: kind, Transform: tr, Robust: f.Robust, SigmaFloor: floor})
	}
	if err := bc.Validate(); err != nil {
		return s, fmt.Errorf("observation.baseline: %w", err)
	}
	s.Baseline = bc
	s.SnapshotInterval = dur(b.SnapshotInterval, time.Hour)
	s.SnapshotRecords = b.SnapshotRecords
	if s.SnapshotRecords == 0 {
		s.SnapshotRecords = 10000
	}
	s.Auto = baseline.AutoLimits{MaxMeanShift: b.AutoPromoteMaxShift, MaxSigmaFactor: b.AutoPromoteMaxSigmaFactor}
	s.Thresholds = anomaly.DefaultThresholds
	if len(b.Bands) == 3 {
		s.Thresholds = anomaly.Thresholds{Elevated: b.Bands[0], Abnormal: b.Bands[1], Critical: b.Bands[2]}
	}
	if err := s.Thresholds.Validate(); err != nil {
		return s, fmt.Errorf("observation.baseline.bands: %w", err)
	}
	return s, nil
}
