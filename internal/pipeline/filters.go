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
}

// ResponseVerdict is a response filter's outcome. Result carries the
// replacement for Transform.
type ResponseVerdict struct {
	Action     Action
	Result     *mcp.CallToolResult
	ReasonCode string
	Finding    string
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
	mu   sync.RWMutex
	req  []entry[RequestFilter]
	resp []entry[ResponseFilter]
	seq  int
}

// NewFilters returns chains holding the default mandatory filters.
func NewFilters() *Filters {
	f := &Filters{}
	if err := f.RegisterRequest(SchemaValidate{}, Registration{Order: 100, Mandatory: true}); err != nil {
		panic(err)
	}
	return f
}

func (f *Filters) known(id string) bool {
	for _, e := range f.req {
		if e.id == id {
			return true
		}
	}
	for _, e := range f.resp {
		if e.id == id {
			return true
		}
	}
	return false
}

// RegisterRequest adds a request filter. IDs are unique across both chains.
func (f *Filters) RegisterRequest(rf RequestFilter, reg Registration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rf.ID() == "" || f.known(rf.ID()) {
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
	if rf.ID() == "" || f.known(rf.ID()) {
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
// non-nil verdict means the request is blocked. A filter error blocks with
// ReasonFilterError (fail closed).
func (f *Filters) RunRequest(ctx context.Context, call *Call, args json.RawMessage) (json.RawMessage, []string, *RequestVerdict) {
	f.mu.RLock()
	chain := slices.Clone(f.req)
	f.mu.RUnlock()
	if missing := f.Unavailable(call.Obligations.Filters); len(missing) > 0 {
		return args, nil, &RequestVerdict{Action: Block, ReasonCode: ReasonFilterUnavailable, Finding: "required filters unavailable: " + strings.Join(missing, ", ")}
	}
	var applied []string
	for _, e := range chain {
		if !selected(e.id, e.reg, call) {
			continue
		}
		v, err := e.f.FilterRequest(ctx, call, args)
		applied = append(applied, e.id)
		if err != nil {
			return args, applied, &RequestVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " failed"}
		}
		switch v.Action {
		case Pass:
		case Transform:
			if !json.Valid(v.Arguments) {
				return args, applied, &RequestVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " produced invalid arguments"}
			}
			args = v.Arguments
		default:
			if v.ReasonCode == "" {
				v.ReasonCode = "FILTER_BLOCKED"
			}
			return args, applied, &v
		}
	}
	return args, applied, nil
}

// RunResponse applies the selected response filters in order.
func (f *Filters) RunResponse(ctx context.Context, call *Call, res *mcp.CallToolResult) (*mcp.CallToolResult, []string, *ResponseVerdict) {
	f.mu.RLock()
	chain := slices.Clone(f.resp)
	f.mu.RUnlock()
	var applied []string
	for _, e := range chain {
		if !selected(e.id, e.reg, call) {
			continue
		}
		v, err := e.f.FilterResponse(ctx, call, res)
		applied = append(applied, e.id)
		if err != nil {
			return nil, applied, &ResponseVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " failed"}
		}
		switch v.Action {
		case Pass:
		case Transform:
			if v.Result == nil {
				return nil, applied, &ResponseVerdict{Action: Block, ReasonCode: ReasonFilterError, Finding: "filter " + e.id + " produced no result"}
			}
			res = v.Result
		default:
			if v.ReasonCode == "" {
				v.ReasonCode = "FILTER_WITHHELD"
			}
			return nil, applied, &v
		}
	}
	return res, applied, nil
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
