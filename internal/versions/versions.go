// Package versions is the version purge of the Data Lifecycle & Memory
// Manager (E-28): POST /api/v1/versions/purge deletes a stored rule,
// route, policy, server, tool, profile or baseline-snapshot version only
// when no unexpired audit record references it (SR-6.14-1). The Evidence
// Journal is never expired, so every journal event counts.
package versions

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
)

// Version kinds of SR-6.14-1.
const (
	KindRule             = "rule"
	KindRoute            = "route"
	KindPolicy           = "policy_revision"
	KindServer           = "server_revision"
	KindTool             = "tool_revision"
	KindProfile          = "profile"
	KindBaselineSnapshot = "baseline_snapshot"
)

// Kinds lists every version kind the route accepts.
var Kinds = []string{KindRule, KindRoute, KindPolicy, KindServer, KindTool, KindProfile, KindBaselineSnapshot}

// Reason codes of the purge evidence and refusals.
const (
	ReasonReferenced = "VERSION_REFERENCED"
	ReasonRetained   = "VERSION_RETAINED"
	ReasonPurged     = "VERSION_PURGED"
	// ReasonPurgeFailed follows a receipt when the deletion then failed.
	ReasonPurgeFailed = "VERSION_PURGE_FAILED"
)

// Errors of Purge.
var (
	ErrKind       = errors.New("versions: unknown version kind")
	ErrReferenced = errors.New("versions: the version is referenced by unexpired audit records")
	ErrRetained   = errors.New("versions: versions of this kind are retained and cannot be purged")
)

// Purger deletes one stored version of a kind. It is called only after
// the reference check passed. It checks that the version exists and may
// be deleted, then calls receipt, which commits the purge receipt, and
// deletes the version only when receipt returned nil.
type Purger func(id string, receipt func() error) error

// Service purges versions.
type Service struct {
	// JournalDir is the Evidence Journal directory scanned for references.
	JournalDir string
	// Evidence records the refusals and the purge receipts.
	Evidence audit.Recorder
	purgers  map[string]Purger
}

// SetPurger registers the deletion of one kind's versions. A kind without
// a purger is retained (the purge is refused with VERSION_RETAINED).
func (s *Service) SetPurger(kind string, p Purger) {
	if s.purgers == nil {
		s.purgers = map[string]Purger{}
	}
	s.purgers[kind] = p
}

// Reference is the first audit record found referencing a version.
type Reference struct {
	Count   int    `json:"count"`
	EventID string `json:"first_event_id,omitempty"`
}

// references reports whether value names the version id: the value is the
// ID itself or a path below it ("<policy revision>/<profile>/<rule>",
// "<server revision>/<tool>").
func references(value, id string) bool {
	return value == id || strings.HasPrefix(value, id+"/")
}

// detailRefers walks an event detail for a string naming id.
func detailRefers(v any, id string) bool {
	switch x := v.(type) {
	case string:
		return references(x, id)
	case []any:
		return slices.ContainsFunc(x, func(e any) bool { return detailRefers(e, id) })
	case map[string]any:
		for _, e := range x {
			if detailRefers(e, id) {
				return true
			}
		}
	}
	return false
}

// eventRefers reports whether one audit record references id, through a
// revision field or any value of its detail. The purge's own refusals and
// receipts name the version but are not references to it.
func eventRefers(ev audit.Event, id string) bool {
	if ev.Origin == "E-28" && slices.Contains([]string{ReasonReferenced, ReasonRetained, ReasonPurged, ReasonPurgeFailed}, ev.ReasonCode) {
		return false
	}
	for _, f := range []string{ev.PolicyRevision, ev.ServerRevision, ev.ToolRevision, ev.DecisionID} {
		if f != "" && references(f, id) {
			return true
		}
	}
	return ev.Detail != nil && detailRefers(ev.Detail, id)
}

// References counts the unexpired audit records that reference id.
func (s *Service) References(id string) (Reference, error) {
	var ref Reference
	evs, err := audit.ReadEvents(s.JournalDir)
	if err != nil {
		return ref, err
	}
	for _, ev := range evs {
		if eventRefers(ev, id) {
			if ref.Count == 0 {
				ref.EventID = ev.EventID
			}
			ref.Count++
		}
	}
	return ref, nil
}

func (s *Service) record(ev audit.Event) error {
	if s.Evidence == nil {
		return nil
	}
	ev.Class, ev.Origin, ev.PolicyStatus = "admin", "E-28", "not_evaluated"
	return s.Evidence.Commit(ev)
}

// Purge deletes the version kind/id for actor. It refuses a version that
// an unexpired audit record references (ErrReferenced) and a kind without
// a purger (ErrRetained); each refusal is recorded. The purge receipt is
// committed before the version is deleted.
func (s *Service) Purge(kind, id, actor string) (Reference, error) {
	if !slices.Contains(Kinds, kind) {
		return Reference{}, fmt.Errorf("%w: %q", ErrKind, kind)
	}
	ref, err := s.References(id)
	if err != nil {
		return ref, err
	}
	detail := map[string]any{"kind": kind, "version": id, "actor": actor}
	if ref.Count > 0 {
		detail["references"], detail["first_event_id"] = ref.Count, ref.EventID
		if err := s.record(audit.Event{Outcome: "refused", ReasonCode: ReasonReferenced, Detail: detail}); err != nil {
			return ref, err
		}
		return ref, ErrReferenced
	}
	p := s.purgers[kind]
	if p == nil {
		if err := s.record(audit.Event{Outcome: "refused", ReasonCode: ReasonRetained, Detail: detail}); err != nil {
			return ref, err
		}
		return ref, ErrRetained
	}
	receipted := false
	err = p(id, func() error {
		receipted = true
		return s.record(audit.Event{Outcome: "purged", ReasonCode: ReasonPurged, Detail: detail})
	})
	if err != nil && receipted {
		detail["error"] = err.Error()
		_ = s.record(audit.Event{Outcome: "failed", ReasonCode: ReasonPurgeFailed, Detail: detail})
	}
	return ref, err
}

// Register adds POST /api/v1/versions/purge (Appendix C "Purge" row:
// Administrator only).
func (s *Service) Register(admin *adminapi.Server) {
	admin.Handle("POST /api/v1/versions/purge", s.handle)
}

// ErrNotFound may be wrapped by a Purger for an unknown version.
var ErrNotFound = errors.New("versions: version not found")

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	if !slices.Contains(Kinds, body.Kind) {
		writeError(w, http.StatusBadRequest, "bad_request", "kind must be one of "+strings.Join(Kinds, ", "))
		return
	}
	if strings.TrimSpace(body.Version) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "version is required")
		return
	}
	ref, err := s.Purge(body.Kind, body.Version, adminapi.ActorOf(r))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"kind": body.Kind, "version": body.Version, "purged": true})
	case errors.Is(err, ErrReferenced):
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": ReasonReferenced,
			"message": fmt.Sprintf("%d unexpired audit records reference %s; it is retained", ref.Count, body.Version)},
			"references": ref})
	case errors.Is(err, ErrRetained):
		writeError(w, http.StatusConflict, ReasonRetained, err.Error())
	case errors.Is(err, baseline.ErrPromoted):
		writeError(w, http.StatusConflict, "VERSION_IN_USE", err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// BaselinePurger deletes baseline snapshots from st. An unknown snapshot
// is ErrNotFound and the promoted one is refused, both before the receipt.
func BaselinePurger(st *baseline.SnapshotStore) Purger {
	return func(id string, receipt func() error) error {
		if _, err := st.Load(id); errors.Is(err, baseline.ErrNotFound) {
			return fmt.Errorf("%w: %w", ErrNotFound, err)
		} else if err != nil && !errors.Is(err, baseline.ErrDigest) {
			return err
		}
		if prom, err := st.Promoted(); err != nil {
			return err
		} else if prom == id {
			return fmt.Errorf("%w: %s", baseline.ErrPromoted, id)
		}
		if err := receipt(); err != nil {
			return err
		}
		return st.Delete(id)
	}
}
