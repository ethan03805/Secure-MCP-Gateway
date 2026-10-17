package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// Held calls (FR-3.19). The MCP endpoint answers in JSON (FR-1.6), but a
// call parked for an approval needs keep-alives, which only an event
// stream can carry. A tools/call request is therefore served by an SDK
// handler in event-stream mode behind a heldWriter that buffers the
// output: when the call finishes without having been held, the single
// response event is re-encoded as an application/json body, so the
// harness sees exactly what JSON mode would have produced; when the
// Approval Service sends the first keep-alive, the writer commits to
// text/event-stream and every later event and keep-alive goes out as it
// is written.

const ctxHeld ctxKey = 100

// serveMCP routes one authenticated MCP POST to the JSON handler, or, for
// a single tools/call, to the event-stream handler behind a heldWriter.
func (g *Gateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	if !g.isToolCall(r) {
		g.handler.ServeHTTP(w, r)
		return
	}
	hw := &heldWriter{w: w, hdr: http.Header{}}
	g.streamHandler.ServeHTTP(hw, r.WithContext(context.WithValue(r.Context(), ctxHeld, hw)))
	hw.finish()
}

// isToolCall peeks at the body (within the CP-07 bound, which the SDK
// enforces again) and reports whether it is one tools/call request. The
// body is restored for the SDK.
func (g *Gateway) isToolCall(r *http.Request) bool {
	limit := g.cfg.Limits.RequestBodyBytes
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	if err != nil || int64(len(buf)) > limit {
		return false
	}
	var m struct {
		Method string `json:"method"`
	}
	return json.Unmarshal(buf, &m) == nil && m.Method == "tools/call"
}

// heldWriter buffers an event-stream response until the call is held
// (startStream) or finishes (finish). It serializes the SDK's writes with
// keep-alive comments; the SDK writes each event with one Write, so a
// comment never splits an event.
type heldWriter struct {
	mu        sync.Mutex
	w         http.ResponseWriter
	hdr       http.Header
	status    int
	buf       bytes.Buffer
	streaming bool
	done      bool
}

func (h *heldWriter) Header() http.Header { return h.hdr }

func (h *heldWriter) WriteHeader(code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		return // already sent
	}
	if h.status == 0 {
		h.status = code
	}
}

func (h *heldWriter) Write(b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		return h.w.Write(b)
	}
	return h.buf.Write(b)
}

// Flush implements http.Flusher; it is a no-op until the stream starts.
func (h *heldWriter) Flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		_ = http.NewResponseController(h.w).Flush()
	}
}

func isEventStream(hdr http.Header) bool {
	mt, _, _ := mime.ParseMediaType(hdr.Get("Content-Type"))
	return mt == "text/event-stream"
}

func (h *heldWriter) copyHeaders() {
	for k, v := range h.hdr {
		h.w.Header()[k] = v
	}
}

// startStream commits the response to text/event-stream and writes what
// was buffered. It reports false when the response is not an event stream
// (for example an HTTP error) or has already been sent.
func (h *heldWriter) startStream() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streaming {
		return true
	}
	if h.done || !isEventStream(h.hdr) || (h.status != 0 && h.status != http.StatusOK) {
		return false
	}
	h.copyHeaders()
	h.w.WriteHeader(http.StatusOK)
	_, _ = h.w.Write(h.buf.Bytes())
	h.buf.Reset()
	h.streaming = true
	_ = http.NewResponseController(h.w).Flush()
	return true
}

// comment writes an SSE comment line (a keep-alive that clients ignore).
func (h *heldWriter) comment(text string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.streaming {
		return
	}
	_, _ = io.WriteString(h.w, ": "+strings.ReplaceAll(text, "\n", " ")+"\n\n")
	_ = http.NewResponseController(h.w).Flush()
}

// finish sends a response that was never streamed: a single event-stream
// message becomes the JSON body JSON mode would have sent; anything else is
// sent as written.
func (h *heldWriter) finish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.done = true
	if h.streaming {
		return
	}
	status := h.status
	if status == 0 {
		status = http.StatusOK
	}
	if isEventStream(h.hdr) && status == http.StatusOK {
		if data, ok := singleEventData(h.buf.Bytes()); ok {
			h.copyHeaders()
			hdr := h.w.Header()
			hdr.Set("Content-Type", "application/json")
			hdr.Del("Connection")
			h.w.WriteHeader(status)
			_, _ = h.w.Write(data)
			return
		}
	}
	h.copyHeaders()
	h.w.WriteHeader(status)
	_, _ = h.w.Write(h.buf.Bytes())
}

// singleEventData returns the data of the only event in an SSE body.
func singleEventData(b []byte) ([]byte, bool) {
	var data []byte
	events := 0
	for block := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n\n") {
		var lines []string
		for line := range strings.SplitSeq(block, "\n") {
			if v, ok := strings.CutPrefix(line, "data:"); ok {
				lines = append(lines, strings.TrimPrefix(v, " "))
			}
		}
		if len(lines) > 0 {
			events++
			data = []byte(strings.Join(lines, "\n"))
		}
	}
	return data, events == 1
}

// keepAlive returns the Progress function of an approval request: it
// commits the held call to an event stream and sends a
// notifications/progress message when the request carries a progress token,
// or an SSE comment line otherwise (FR-3.19).
//
// The progress values continue in the call's progressRelay, so backend
// progress relayed after the approval keeps increasing (FR-1.39).
func (g *Gateway) keepAlive(ctx context.Context, prog *progressRelay) func(string) {
	hw, _ := ctx.Value(ctxHeld).(*heldWriter)
	return func(msg string) {
		streaming := hw != nil && hw.startStream()
		if prog.keepAlive(msg) {
			return
		}
		if streaming {
			hw.comment("keep-alive " + msg)
		}
	}
}
