package connector

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// RegisterRoutes adds the /api/v1/contextforge routes (docs/api/contextforge.md).
// The role matrix (internal/adminapi/rolematrix.go) opens the reads to
// Operators and Auditors and the import actions to Operators (FR-22.5).
func (c *Connector) RegisterRoutes(s *adminapi.Server) {
	s.Handle("GET /api/v1/contextforge/status", c.apiStatus)
	s.Handle("GET /api/v1/contextforge/catalog", c.apiList)
	s.Handle("GET /api/v1/contextforge/catalog/{id}", c.apiShow)
	s.Handle("POST /api/v1/contextforge/catalog/{id}/import", c.apiImport)
	s.Handle("GET /api/v1/contextforge/proposals", c.apiProposals)
	s.Handle("GET /api/v1/contextforge/proposals/{id}", c.apiProposal)
	s.Handle("POST /api/v1/contextforge/proposals/{id}/decision", c.apiDecide)
	s.Handle("POST /api/v1/contextforge/instance/start", c.apiInstance(true))
	s.Handle("POST /api/v1/contextforge/instance/stop", c.apiInstance(false))
	s.Handle("POST /api/v1/contextforge/instance/uninstall", c.apiUninstall)
	s.Handle("POST /api/v1/contextforge/starter-set", c.apiStarterSet)
}

func (c *Connector) apiStarterSet(w http.ResponseWriter, r *http.Request) {
	ps, err := c.ProposeStarterSet(adminapi.Actor(r))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"proposals": ps})
}

func (c *Connector) apiUninstall(w http.ResponseWriter, r *http.Request) {
	rep, err := c.Uninstall(r.Context(), adminapi.Actor(r))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uninstall": rep, "instance": c.Instance()})
}

func (c *Connector) apiInstance(start bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		c.demandMu.Lock()
		c.operatorHold = start
		c.demandMu.Unlock()
		if start {
			err = c.StartInstance(r.Context(), adminapi.Actor(r))
		} else {
			err = c.StopInstance(r.Context(), adminapi.Actor(r))
		}
		if err != nil {
			writeRefusal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instance": c.Instance()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func writeRefusal(w http.ResponseWriter, err error) {
	var de *DecisionError
	switch {
	case errors.As(err, &de):
		st := http.StatusConflict
		if de.Code == "not_found" {
			st = http.StatusNotFound
		}
		writeErr(w, st, de.Code, de.Msg)
	case errors.Is(err, contextforge.ErrUnknownEntry):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	default:
		code := packaging.ReasonOf(err)
		st := http.StatusConflict
		switch code {
		case "":
			code, st = "internal_error", http.StatusInternalServerError
		case contextforge.ReasonCatalogDigestMismatch, contextforge.ReasonCatalogInvalid:
			st = http.StatusServiceUnavailable
		}
		writeErr(w, st, code, err.Error())
	}
}

// EntryView is one catalog entry as G-15 and `smcpctl catalog list` show
// it (FR-22.4). Every value is catalog text to be shown inert; logo_url
// is never loaded.
type EntryView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`
	Category    string   `json:"category"`
	Class       string   `json:"class"`
	Reasons     []string `json:"unsupported_reasons,omitempty"`
	AuthType    string   `json:"auth_type"`
	URL         string   `json:"url,omitempty"`
	Install     string   `json:"install,omitempty"`
	Repo        string   `json:"repo,omitempty"`
	Tags        []string `json:"tags"`
	Description string   `json:"description,omitempty"`
	EntrySHA256 string   `json:"entry_sha256"`
	entryState
}

func (c *Connector) view(e *contextforge.Entry) EntryView {
	class, reasons := e.Classify()
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	return EntryView{ID: e.ID, Name: e.Name, Provider: e.Provider, Category: e.Category, Class: class, Reasons: reasons,
		AuthType: e.AuthType, URL: e.URL, Install: e.Install, Repo: e.Repo, Tags: tags, Description: e.Description,
		EntrySHA256: e.SHA256(), entryState: c.stateOf(e)}
}

// Filter selects catalog entries (FR-22.4): exact class, category and
// auth type, and a case-insensitive text search over the id, name,
// provider, category, description, URL, install text and tags.
type Filter struct{ Class, Category, AuthType, Query string }

// List returns the entries matching f.
func (c *Connector) List(f Filter) ([]EntryView, error) {
	if c.catErr != nil {
		return nil, c.catErr
	}
	q := lower(strings.TrimSpace(f.Query))
	out := []EntryView{}
	for _, e := range c.cat.Entries {
		v := c.view(e)
		if (f.Class != "" && v.Class != f.Class) || (f.Category != "" && !strings.EqualFold(v.Category, f.Category)) ||
			(f.AuthType != "" && !strings.EqualFold(v.AuthType, f.AuthType)) {
			continue
		}
		if q != "" {
			hay := lower(strings.Join(append([]string{v.ID, v.Name, v.Provider, v.Category, v.Description, v.URL, v.Install}, v.Tags...), "\n"))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// Status is the Connector's state for G-15 and `smcpctl catalog status`.
type Status struct {
	Bundled        bool         `json:"bundled"`
	CatalogOrigin  string       `json:"catalog_origin,omitempty"`
	CatalogRelease string       `json:"catalog_release,omitempty"`
	CatalogSHA256  string       `json:"catalog_sha256,omitempty"`
	CatalogEntries int          `json:"catalog_entries"`
	CatalogError   string       `json:"catalog_error,omitempty"`
	CatalogReason  string       `json:"catalog_reason_code,omitempty"`
	Lock           LockView     `json:"release_lock"`
	ImportKey      KeyView      `json:"import_key"`
	Instance       InstanceView `json:"instance"`
}

// LockView summarizes the release lock.
type LockView struct {
	Version     string   `json:"version"`
	IndexDigest string   `json:"image_index_digest"`
	StarterSet  []string `json:"starter_set"`
}

// KeyView describes the catalog import key; an Administrator compares the
// key ID before enrolling it (FR-7.10).
type KeyView struct {
	KeyID     string   `json:"key_id"`
	PublicKey string   `json:"public_key"`
	Enrolled  bool     `json:"enrolled"`
	Classes   []string `json:"classes,omitempty"`
}

// Status reports the Connector's state.
func (c *Connector) Status() Status {
	l := contextforge.ReleaseLock().ContextForge
	st := Status{Bundled: c.o.Config.ContextForge.Bundled,
		Lock: LockView{Version: l.Version, IndexDigest: l.Image.IndexDigest, StarterSet: slices.Clone(l.StarterSet)}}
	if c.catErr != nil {
		st.CatalogError, st.CatalogReason = c.catErr.Error(), packaging.ReasonOf(c.catErr)
	} else {
		st.CatalogOrigin, st.CatalogRelease, st.CatalogSHA256, st.CatalogEntries = c.cat.Origin, c.cat.Release, c.cat.SHA256, len(c.cat.Entries)
	}
	enrolled, classes := c.keyEnrolled()
	st.ImportKey = KeyView{KeyID: c.KeyID(), PublicKey: strings.TrimSpace(string(c.pub)), Enrolled: enrolled, Classes: classes}
	st.Instance = c.Instance()
	return st
}

func (c *Connector) apiStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, c.Status())
}

func (c *Connector) apiList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{Class: q.Get("class"), Category: q.Get("category"), AuthType: q.Get("auth_type"), Query: q.Get("q")}
	switch f.Class {
	case "", contextforge.ClassLocal, contextforge.ClassHosted, contextforge.ClassUnsupported:
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "class must be local, hosted or unsupported")
		return
	}
	list, err := c.List(f)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalog_sha256": c.cat.SHA256, "origin": c.cat.Origin, "release": c.cat.Release,
		"total": len(c.cat.Entries), "entries": list})
}

func (c *Connector) apiShow(w http.ResponseWriter, r *http.Request) {
	e, err := c.entry(r.PathValue("id"))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	d, err := contextforge.DraftImport(c.cat, e.ID, contextforge.ImportOptions{})
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entry": c.view(e), "fields": e.Raw, "draft": d})
}

func (c *Connector) apiImport(w http.ResponseWriter, r *http.Request) {
	var in LocalImport
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be a local import object: "+err.Error())
		return
	}
	p, err := c.ProposeLocal(r.PathValue("id"), in, adminapi.Actor(r))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"proposal": p})
}

func (c *Connector) apiProposals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"proposals": c.Proposals()})
}

func (c *Connector) apiProposal(w http.ResponseWriter, r *http.Request) {
	p, ok := c.Proposal(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "no proposal "+r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p})
}

func (c *Connector) apiDecide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Accept          *bool  `json:"accept"`
		PresentedSHA256 string `json:"presented_sha256"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Accept == nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {accept, presented_sha256}")
		return
	}
	p, err := c.Decide(r.PathValue("id"), *body.Accept, body.PresentedSHA256, adminapi.Actor(r))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposal": p})
}
