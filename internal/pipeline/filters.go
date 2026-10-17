package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Action is a filter verdict.
type Action int

const (
	// Pass lets the call continue unchanged.
	Pass Action = iota
	// Block refuses the request (request filters) or withholds the result
	// (response filters).
	Block
	// Transform replaces the arguments or the result and continues.
	Transform
)

// RequestVerdict is a request filter's outcome. Arguments carries the
// replacement for Transform. ReasonCode and Finding explain Block and
// Transform; Finding is returned to the harness, so it must not echo secret
// argument content.
type RequestVerdict struct {
	Action     Action
	Arguments  json.RawMessage
	ReasonCode string
	Finding    string
	// Findings are the structured detections behind the verdict, including
	// tag-only findings of a Pass (FR-4.4, FR-4.17).
	Findings []Finding
}

// ResponseVerdict is a response filter's outcome. Result carries the
// replacement for Transform.
type ResponseVerdict struct {
	Action     Action
	Result     *mcp.CallToolResult
	ReasonCode string
	Finding    string
	Findings   []Finding
}

// RequestFilter is one stage of the Request Inspection Pipeline (E-09,
// FR-4.5). ID is the stable filter ID named in policy obligations and in
// provenance.
type RequestFilter interface {
	ID() string
	FilterRequest(ctx context.Context, call *Call, args json.RawMessage) (RequestVerdict, error)
}

// ResponseFilter is one stage of the Response Inspection Pipeline (E-11).
type ResponseFilter interface {
	ID() string
	FilterResponse(ctx context.Context, call *Call, res *mcp.CallToolResult) (ResponseVerdict, error)
}

// Registration places a filter in a chain. Filters run in ascending Order,
// ties in registration order. A Mandatory filter runs on every call; any
// other filter runs only when the decision's obligations name its ID.
type Registration struct {
	Order     int
	Mandatory bool
}

// Reason codes the chains produce themselves.
const (
	ReasonFilterError       = "FILTER_ERROR"
	ReasonFilterUnavailable = "FILTER_UNAVAILABLE"
	ReasonFilterTimeout     = "FILTER_TIMEOUT"
)

type entry[F any] struct {
	f   F
	id  string
	reg Registration
	seq int
}

// Filters holds the request and response chains. It is safe for concurrent
// use; registration normally happens before the Gateway serves.
type Filters struct {
	mu       sync.RWMutex
	req      []entry[RequestFilter]
	resp     []entry[ResponseFilter]
	seq      int
	deadline time.Duration
	obs      []FilterObserver
}

// NewFilters returns chains holding the default mandatory filters.
func NewFilters() *Filters {
	f := &Filters{}
	if err := f.RegisterRequest(SchemaValidate{}, Registration{Order: 100, Mandatory: true}); err != nil {
		panic(err)
	}
	return f
}

func (f *Filters) known(id string) bool { return f.knownReq(id) || f.knownResp(id) }

func (f *Filters) knownReq(id string) bool {
	return slices.ContainsFunc(f.req, func(e entry[RequestFilter]) bool { return e.id == id })
}

func (f *Filters) knownResp(id string) bool {
	return slices.ContainsFunc(f.resp, func(e entry[ResponseFilter]) bool { return e.id == id })
}

// RegisterRequest adds a request filter. IDs are unique within a chain; the
// same ID may name a request and a response filter (FR-4.5 and FR-4.6 both
// name `size-limit`, `secret-fingerprint` and `unicode-control`), and an
// obligation naming it selects both.
func (f *Filters) RegisterRequest(rf RequestFilter, reg Registration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rf.ID() == "" || f.knownReq(rf.ID()) {
		return fmt.Errorf("filter ID %q empty or already registered", rf.ID())
	}
	f.seq++
	f.req = append(f.req, entry[RequestFilter]{rf, rf.ID(), reg, f.seq})
	sort.SliceStable(f.req, func(i, j int) bool { return less(f.req[i].reg, f.req[i].seq, f.req[j].reg, f.req[j].seq) })
	return nil
}

// RegisterResponse adds a response filter.
func (f *Filters) RegisterResponse(rf ResponseFilter, reg Registration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rf.ID() == "" || f.knownResp(rf.ID()) {
		return fmt.Errorf("filter ID %q empty or already registered", rf.ID())
	}
	f.seq++
	f.resp = append(f.resp, entry[ResponseFilter]{rf, rf.ID(), reg, f.seq})
	sort.SliceStable(f.resp, func(i, j int) bool { return less(f.resp[i].reg, f.resp[i].seq, f.resp[j].reg, f.resp[j].seq) })
	return nil
}

func less(a Registration, as int, b Registration, bs int) bool {
	if a.Order != b.Order {
		return a.Order < b.Order
	}
	return as < bs
}

// Unavailable returns the obligation filter IDs no chain provides. A call
// whose obligations name an unavailable filter must be refused.
func (f *Filters) Unavailable(ids []string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []string
	for _, id := range ids {
		if !f.known(id) {
			out = append(out, id)
		}
	}
	return out
}

func selected(id string, reg Registration, call *Call) bool {
	return reg.Mandatory || slices.Contains(call.Obligations.Filters, id)
}

// RunRequest applies the selected request filters in order. It returns the
// possibly transformed arguments and the IDs of the filters that ran. A
// non-nil verdict means the request is blocked. A filter error, panic or a
// chain that exceeds the deadline blocks (fail closed, SR-5.10-1).
func (f *Filters) RunRequest(ctx context.Context, call *Call, args json.RawMessage) (json.RawMessage, []string, *RequestVerdict) {
	f.mu.RLock()
	chain := slices.Clone(f.req)
	deadline := f.deadlineLocked()
	f.mu.RUnlock()
	insp := call.inspection()
	if missing := f.Unavailable(call.Obligations.Filters); len(missing) > 0 {
		return args, nil, &RequestVerdict{Action: Block, ReasonCode: ReasonFilterUnavailable, Finding: "required filters unavailable: " + strings.Join(missing, ", ")}
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	var applied []string
	var runs []FilterRun
	defer func() { f.observe(call, StageRequest, runs) }()
	for _, e := range chain {
		if !selected(e.id, e.reg, call) {
			continue
		}
		start := time.Now()
		v, err := runBounded(ctx, func() (RequestVerdict, error) { return e.f.FilterRequest(ctx, call, args) })
		run := FilterRun{Stage: StageRequest, Filter: e.id, Version: versionOf(e.f), Action: v.Action, ReasonCode: v.ReasonCode, Findings: v.Findings, Duration: time.Since(start)}
		applied = append(applied, e.id)
		if err != nil {
			run.Action, run.ReasonCode, run.Findings = Block, errReason(err), nil
			runs = append(runs, run)
			insp.add(run)
			return args, applied, &RequestVerdict{Action: Block, ReasonCode: run.ReasonCode, Finding: "filter " + e.id + " " + errText(err)}
		}
		switch v.Action {
		case Pass:
		case Transform:
			if !json.Valid(v.Arguments) {
				run.Action, run.ReasonCode = Block, ReasonFilterError
				runs = append(runs, run)
				insp.add(run)
				return args, applied, &RequestVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " produced invalid arguments"}
			}
			args = v.Arguments
		default:
			if v.ReasonCode == "" {
				v.ReasonCode = "FILTER_BLOCKED"
			}
			run.Action, run.ReasonCode = Block, v.ReasonCode
			runs = append(runs, run)
			insp.add(run)
			return args, applied, &v
		}
		runs = append(runs, run)
		insp.add(run)
	}
	return args, applied, nil
}

// RunResponse applies the selected response filters in order. A non-nil
// verdict means the result is withheld.
func (f *Filters) RunResponse(ctx context.Context, call *Call, res *mcp.CallToolResult) (*mcp.CallToolResult, []string, *ResponseVerdict) {
	f.mu.RLock()
	chain := slices.Clone(f.resp)
	deadline := f.deadlineLocked()
	f.mu.RUnlock()
	insp := call.inspection()
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	var applied []string
	var runs []FilterRun
	defer func() { f.observe(call, StageResponse, runs) }()
	for _, e := range chain {
		if !selected(e.id, e.reg, call) {
			continue
		}
		start := time.Now()
		cur := res
		v, err := runBounded(ctx, func() (ResponseVerdict, error) { return e.f.FilterResponse(ctx, call, cur) })
		run := FilterRun{Stage: StageResponse, Filter: e.id, Version: versionOf(e.f), Action: v.Action, ReasonCode: v.ReasonCode, Findings: v.Findings, Duration: time.Since(start)}
		applied = append(applied, e.id)
		if err != nil {
			run.Action, run.ReasonCode, run.Findings = Block, errReason(err), nil
			runs = append(runs, run)
			insp.add(run)
			return nil, applied, &ResponseVerdict{Action: Block, ReasonCode: run.ReasonCode, Finding: "filter " + e.id + " " + errText(err)}
		}
		switch v.Action {
		case Pass:
		case Transform:
			if v.Result == nil {
				run.Action, run.ReasonCode = Block, ReasonFilterError
				runs = append(runs, run)
				insp.add(run)
				return nil, applied, &ResponseVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " produced no result"}
			}
			res = v.Result
		default:
			if v.ReasonCode == "" {
				v.ReasonCode = "FILTER_WITHHELD"
			}
			run.Action, run.ReasonCode = Block, v.ReasonCode
			runs = append(runs, run)
			insp.add(run)
			return nil, applied, &v
		}
		runs = append(runs, run)
		insp.add(run)
	}
	return res, applied, nil
}

// errFilterTimeout marks a chain that exceeded its deadline.
var errFilterTimeout = errors.New("exceeded the filter deadline")

type filterPanic struct{ v any }

func (p filterPanic) Error() string { return fmt.Sprintf("panicked: %v", p.v) }

func errReason(err error) string {
	if errors.Is(err, errFilterTimeout) {
		return ReasonFilterTimeout
	}
	return ReasonFilterError
}

func errText(err error) string {
	if errors.Is(err, errFilterTimeout) {
		return "exceeded the filter deadline"
	}
	return "failed"
}

// runBounded runs fn on its own goroutine and gives up when ctx ends, so a
// slow or stuck filter cannot hold the call past the CP-14 deadline. A
// panic is converted to an error. A filter that ignores ctx keeps running
// until it returns; its result is discarded.
func runBounded[V any](ctx context.Context, fn func() (V, error)) (V, error) {
	type out struct {
		v   V
		err error
	}
	ch := make(chan out, 1)
	go func() {
		var o out
		defer func() {
			if r := recover(); r != nil {
				o.err = filterPanic{r}
			}
			ch <- o
		}()
		o.v, o.err = fn()
	}()
	select {
	case o := <-ch:
		return o.v, o.err
	case <-ctx.Done():
		var zero V
		return zero, errFilterTimeout
	}
}

// SchemaValidate is the schema-validate request filter of FR-4.5: it
// validates the arguments against the tool's input schema. Validation is
// bounded by the schema itself; the CP-36 limits are not yet enforced.
type SchemaValidate struct{}

// ID implements RequestFilter.
func (SchemaValidate) ID() string { return "schema-validate" }

// ReasonSchemaInvalid is the reason code of a schema-validate block.
const ReasonSchemaInvalid = "SCHEMA_INVALID"

// FilterRequest implements RequestFilter.
func (SchemaValidate) FilterRequest(_ context.Context, call *Call, args json.RawMessage) (RequestVerdict, error) {
	if finding := ValidateArguments(call.InputSchema, args); finding != "" {
		return RequestVerdict{Action: Block, ReasonCode: ReasonSchemaInvalid, Finding: finding}, nil
	}
	return RequestVerdict{Action: Pass}, nil
}

// schemaCache compiles each backend input schema once. The key is the
// schema's JSON, so a changed schema compiles anew; the cache is bounded.
var schemaCache = struct {
	sync.Mutex
	m map[string]*jsonschema.Schema
}{m: map[string]*jsonschema.Schema{}}

const schemaCacheMax = 4096

var errSchema = errors.New("schema")

func compileSchema(raw []byte) (*jsonschema.Schema, error) {
	key := string(raw)
	schemaCache.Lock()
	c, ok := schemaCache.m[key]
	schemaCache.Unlock()
	if ok {
		return c, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w not parseable", errSchema)
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("tool.json", doc); err != nil {
		return nil, fmt.Errorf("%w not loadable", errSchema)
	}
	c, err = comp.Compile("tool.json")
	if err != nil {
		return nil, fmt.Errorf("%w does not compile: %w", errSchema, err)
	}
	schemaCache.Lock()
	if len(schemaCache.m) >= schemaCacheMax {
		clear(schemaCache.m)
	}
	schemaCache.m[key] = c
	schemaCache.Unlock()
	return c, nil
}

// ValidateArguments returns an empty string when args conform to schema,
// otherwise a one-line finding.
func ValidateArguments(schema any, args json.RawMessage) string {
	raw, err := json.Marshal(schema)
	if err != nil {
		return "schema not serializable"
	}
	compiled, err := compileSchema(raw)
	if err != nil {
		return err.Error()
	}
	var inst any = map[string]any{}
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &inst); err != nil {
			return "arguments are not valid JSON"
		}
	}
	if err := compiled.Validate(inst); err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "\n"); i > 0 {
			msg = msg[:i]
		}
		return msg
	}
	return ""
}
