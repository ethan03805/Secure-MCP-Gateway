package southbound

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"time"
)

// event is one Server-Sent Event of a response stream.
type event struct {
	ID    string
	Name  string
	Data  []byte
	Retry time.Duration
	// Oversized is set when the event's data exceeded the bound; Data then
	// holds only the bounded prefix.
	Oversized bool
}

// sseReader parses an event stream (WHATWG HTML, Server-sent events,
// "Interpreting an event stream"). Comment lines, those that start with a
// colon, are ignored (FR-5.30), as are unknown fields. The data of one
// event is bounded by limit; a longer event is reported once as Oversized
// with its prefix and the rest of it is discarded.
type sseReader struct {
	r     *bufio.Reader
	limit int
	// Comments counts ignored comment lines (tests).
	Comments int
}

func newSSEReader(r io.Reader, limit int) *sseReader {
	return &sseReader{r: bufio.NewReaderSize(r, 32<<10), limit: limit}
}

// readLine returns one line without its terminator (CR LF, LF or CR). Of
// a line longer than limit+64 bytes only that many are kept and truncated
// is set; the rest of the line is read and discarded.
func (s *sseReader) readLine() (line []byte, truncated bool, err error) {
	for {
		b, err := s.r.ReadByte()
		if err != nil {
			if (len(line) > 0 || truncated) && errors.Is(err, io.EOF) {
				return line, truncated, nil
			}
			return nil, false, err
		}
		switch b {
		case '\n':
			return line, truncated, nil
		case '\r':
			if nb, err := s.r.Peek(1); err == nil && nb[0] == '\n' {
				_, _ = s.r.ReadByte()
			}
			return line, truncated, nil
		}
		if len(line) >= s.limit+64 {
			truncated = true
			continue
		}
		line = append(line, b)
	}
}

// Next returns the next dispatched event. io.EOF means the stream ended;
// an event in progress at the end is not dispatched, as the standard says.
func (s *sseReader) Next() (event, error) {
	var ev event
	var data bytes.Buffer
	hasData := false
	for {
		line, truncated, err := s.readLine()
		if err != nil {
			return event{}, err
		}
		if len(line) == 0 && !truncated {
			if !hasData {
				// An event without data is not dispatched; its id still
				// updates the last event ID.
				if ev.ID != "" {
					return event{ID: ev.ID}, nil
				}
				ev = event{}
				continue
			}
			ev.Data = data.Bytes()
			return ev, nil
		}
		if line[0] == ':' {
			s.Comments++
			continue
		}
		field, value := line, []byte(nil)
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}
		switch string(field) {
		case "data":
			if ev.Oversized {
				continue
			}
			// The line feed that joins data lines counts against the
			// bound too (found by FuzzSSEReader).
			sep := 0
			if hasData {
				sep = 1
			}
			hasData = true
			if truncated || data.Len()+sep+len(value) > s.limit {
				if sep == 1 && data.Len() < s.limit {
					data.WriteByte('\n')
				}
				data.Write(value[:min(len(value), max(0, s.limit-data.Len()))])
				ev.Oversized = true
				continue
			}
			if sep == 1 {
				data.WriteByte('\n')
			}
			data.Write(value)
		case "id":
			if bytes.IndexByte(value, 0) < 0 && len(value) <= 1024 {
				ev.ID = string(value)
			}
		case "event":
			if len(value) <= 256 {
				ev.Name = string(value)
			}
		case "retry":
			if ms, err := strconv.Atoi(string(value)); err == nil && ms >= 0 {
				ev.Retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}
