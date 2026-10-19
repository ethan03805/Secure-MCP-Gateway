package connector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// hostedProcess sits between the Tool Dispatcher (E-10) and the
// connection to a hosted package's virtual server. It sends each tool
// under the backend name its manifest records (FR-22.10), shows the
// served list under the manifest names so drift detection compares like
// with like, and turns ContextForge's "Unknown tool" result for a tool of
// the manifest into a -32601 error, which the Gateway returns as -31007
// BACKEND_ERROR with backendCode -32601 instead of relaying the text as a
// result (FR-22.33); onUnknown then starts a reconciliation.
type hostedProcess struct {
	pipeline.Process
	toBackend map[string]string
	toName    map[string]string
	onUnknown func(tool string)

	wmu  sync.Mutex
	wbuf []byte

	rmu     sync.Mutex
	r       *bufio.Reader
	pending []byte

	cmu   sync.Mutex
	calls map[string]string // request id -> manifest tool name
}

// renameProcess wraps p for a hosted package whose manifest maps names to
// backend names.
func renameProcess(p pipeline.Process, toBackend map[string]string, onUnknown func(string)) pipeline.Process {
	h := &hostedProcess{Process: p, toBackend: toBackend, toName: map[string]string{}, onUnknown: onUnknown,
		r: bufio.NewReaderSize(p, 64<<10), calls: map[string]string{}}
	for n, b := range toBackend {
		h.toName[b] = n
	}
	return h
}

// Write rewrites whole lines; a partial line waits for its end.
func (h *hostedProcess) Write(p []byte) (int, error) {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	h.wbuf = append(h.wbuf, p...)
	for {
		i := bytes.IndexByte(h.wbuf, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := h.outbound(h.wbuf[:i])
		rest := append([]byte(nil), h.wbuf[i+1:]...)
		h.wbuf = rest
		if _, err := h.Process.Write(append(line, '\n')); err != nil {
			return 0, err
		}
	}
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (h *hostedProcess) outbound(line []byte) []byte {
	var m rpcMsg
	if json.Unmarshal(line, &m) != nil || m.Method != "tools/call" {
		return line
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(m.Params, &params) != nil {
		return line
	}
	var name string
	if json.Unmarshal(params["name"], &name) != nil {
		return line
	}
	backend, ok := h.toBackend[name]
	if !ok {
		return line
	}
	params["name"], _ = json.Marshal(backend)
	m.Params, _ = json.Marshal(params)
	h.cmu.Lock()
	h.calls[string(m.ID)] = name
	h.cmu.Unlock()
	out, err := json.Marshal(m)
	if err != nil {
		return line
	}
	return out
}

// Read returns rewritten lines from the server.
func (h *hostedProcess) Read(p []byte) (int, error) {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	for len(h.pending) == 0 {
		line, err := h.r.ReadBytes('\n')
		if len(line) > 0 {
			h.pending = append(h.inbound(bytes.TrimRight(line, "\n")), '\n')
		}
		if err != nil && len(h.pending) == 0 {
			return 0, err
		}
		if err != nil {
			break
		}
	}
	n := copy(p, h.pending)
	h.pending = h.pending[n:]
	return n, nil
}

func (h *hostedProcess) inbound(line []byte) []byte {
	var m rpcMsg
	if json.Unmarshal(line, &m) != nil || len(m.Result) == 0 {
		return line
	}
	h.cmu.Lock()
	called, isCall := h.calls[string(m.ID)]
	delete(h.calls, string(m.ID))
	h.cmu.Unlock()
	if isCall {
		var r struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if json.Unmarshal(m.Result, &r) == nil && r.IsError && len(r.Content) > 0 && strings.HasPrefix(r.Content[0].Text, "Unknown tool") {
			if h.onUnknown != nil {
				h.onUnknown(called)
			}
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID,
				"error": map[string]any{"code": -32601, "message": "the hosted tool is not served by the bundled ContextForge instance"}})
			return out
		}
		return line
	}
	var list struct {
		Tools []map[string]json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(m.Result, &list) != nil || list.Tools == nil {
		return line
	}
	var res map[string]json.RawMessage
	_ = json.Unmarshal(m.Result, &res)
	for _, t := range list.Tools {
		var n string
		if json.Unmarshal(t["name"], &n) == nil {
			if mn, ok := h.toName[n]; ok {
				t["name"], _ = json.Marshal(mn)
			}
		}
	}
	res["tools"], _ = json.Marshal(list.Tools)
	m.Result, _ = json.Marshal(res)
	out, err := json.Marshal(m)
	if err != nil {
		return line
	}
	return out
}
