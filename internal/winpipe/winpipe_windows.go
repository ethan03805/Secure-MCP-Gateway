//go:build windows

package winpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

const bufferSize = 64 << 10

type addr string

func (a addr) Network() string { return "pipe" }
func (a addr) String() string  { return string(a) }

// Listener accepts connections on a named pipe.
type Listener struct {
	name    string
	sa      *windows.SecurityAttributes
	closeEv windows.Handle

	mu      sync.Mutex
	pending windows.Handle // the instance waiting for the next client
	waiting windows.Handle // the instance an Accept is waiting on
	closed  bool
}

func createInstance(name string, sa *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	h, err := windows.CreateNamedPipe(n, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, bufferSize, bufferSize, 0, sa)
	if err != nil {
		if first && (errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY)) {
			return windows.InvalidHandle, fmt.Errorf("%w (%s: %w)", ErrSquatted, name, err)
		}
		return windows.InvalidHandle, fmt.Errorf("winpipe: create %s: %w", name, err)
	}
	return h, nil
}

// Listen creates the pipe name with the SR-2.8-6 DACL (Entries). It
// returns an error wrapping ErrSquatted when the name exists already.
func Listen(name string, entries []winsec.Entry) (*Listener, error) {
	sa, err := winsec.SecurityAttributes(entries)
	if err != nil {
		return nil, err
	}
	h, err := createInstance(name, sa, true)
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return &Listener{name: name, sa: sa, closeEv: ev, pending: h, waiting: windows.InvalidHandle}, nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr { return addr(l.name) }

// Close implements net.Listener: a blocked Accept returns net.ErrClosed.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	_ = windows.SetEvent(l.closeEv)
	if l.pending != windows.InvalidHandle {
		_ = windows.CloseHandle(l.pending)
		l.pending = windows.InvalidHandle
	}
	return nil
}

// Accept waits for the next client and returns its connection.
func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.pending
	l.pending = windows.InvalidHandle
	if h == windows.InvalidHandle {
		var err error
		if h, err = createInstance(l.name, l.sa, false); err != nil {
			l.mu.Unlock()
			return nil, err
		}
	}
	l.waiting = h
	l.mu.Unlock()
	err := l.connect(h)
	l.mu.Lock()
	l.waiting = windows.InvalidHandle // DACL no longer reads through h
	l.mu.Unlock()
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	sid, err := clientSID(h)
	if err != nil {
		_ = windows.DisconnectNamedPipe(h)
		_ = windows.CloseHandle(h)
		// One client that cannot be identified does not stop the listener:
		// the connection is returned closed and ClientSID reports why.
		return &Conn{name: l.name, refused: err}, nil //nolint:nilerr // reported through ClientSID

	}
	f := os.NewFile(uintptr(h), l.name)
	return &Conn{f: f, name: l.name, sid: sid}, nil
}

// DACL reads the security descriptor of the pipe through a server
// instance of this listener (SR-2.8-6): the instance waiting for a
// client, or a new one kept for the next Accept. It opens no client
// connection, so the answer does not depend on how a serving Gateway
// treats a connection that never authenticates.
func (l *Listener) DACL() (protected, null bool, entries []winsec.Entry, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false, false, nil, net.ErrClosed
	}
	h := l.waiting
	if h == windows.InvalidHandle {
		if l.pending == windows.InvalidHandle {
			if l.pending, err = createInstance(l.name, l.sa, false); err != nil {
				l.pending = windows.InvalidHandle
				return false, false, nil, err
			}
		}
		h = l.pending
	}
	return winsec.DACLHandle(h, windows.SE_KERNEL_OBJECT)
}

// connect waits, interruptibly, for a client to open the instance h.
func (l *Listener) connect(h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return fmt.Errorf("winpipe: connect: %w", err)
	}
	i, err := windows.WaitForMultipleObjects([]windows.Handle{ev, l.closeEv}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if i != windows.WAIT_OBJECT_0 {
		_ = windows.CancelIoEx(h, &ov)
		var n uint32
		_ = windows.GetOverlappedResult(h, &ov, &n, true)
		return net.ErrClosed
	}
	var n uint32
	if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return fmt.Errorf("winpipe: connect: %w", err)
	}
	return nil
}

// clientSID impersonates the connected client at the level it allowed
// (identification for this package's Dial) and reads the user SID of the
// thread token (FR-21.9).
func clientSID(h windows.Handle) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, err := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		return "", fmt.Errorf("winpipe: ImpersonateNamedPipeClient: %w", err)
	}
	var tok windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// Never continue on a thread that still impersonates the client.
		panic("winpipe: RevertToSelf failed: " + rerr.Error())
	}
	if err != nil {
		return "", fmt.Errorf("winpipe: client token: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

// Conn is one pipe connection. ClientSID is the user SID of the client's
// token on a server-side connection.
type Conn struct {
	f       *os.File
	name    string
	sid     string
	refused error // the client could not be identified; Read fails with it
}

// ClientSID returns the client's user SID, or the error that kept it from
// being read (the connection is then already closed).
func (c *Conn) ClientSID() (string, error) {
	if c.refused != nil {
		return "", c.refused
	}
	return c.sid, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.f == nil {
		return 0, c.closedErr()
	}
	n, err := c.f.Read(b)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		err = io.EOF
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.f == nil {
		return 0, c.closedErr()
	}
	return c.f.Write(b)
}

func (c *Conn) closedErr() error {
	if c.refused != nil {
		return c.refused
	}
	return net.ErrClosed
}

// Close implements net.Conn.
func (c *Conn) Close() error {
	if c.f == nil {
		return nil
	}
	return c.f.Close()
}

func (c *Conn) LocalAddr() net.Addr  { return addr(c.name) }
func (c *Conn) RemoteAddr() net.Addr { return addr(c.name) }

func (c *Conn) SetDeadline(t time.Time) error {
	if c.f == nil {
		return nil
	}
	return c.f.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.f == nil {
		return nil
	}
	return c.f.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.f == nil {
		return nil
	}
	return c.f.SetWriteDeadline(t)
}

// Dial opens the pipe as a client, allowing the server to identify but
// not impersonate this process (SECURITY_IDENTIFICATION). A busy pipe is
// retried until ctx ends.
func Dial(ctx context.Context, name string) (net.Conn, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return &Conn{f: os.NewFile(uintptr(h), name), name: name}, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, &net.OpError{Op: "dial", Net: "pipe", Addr: addr(name), Err: err}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// DACL reads the pipe's DACL through a client handle (doctor). The
// handle is a connection: a server that drops a client which sends
// nothing can disconnect it before the read, which then fails with
// ERROR_PIPE_NOT_CONNECTED. The server reads its own pipe with
// Listener.DACL.
func DACL(name string) (protected, null bool, entries []winsec.Entry, err error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, false, nil, err
	}
	h, err := windows.CreateFile(n, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return false, false, nil, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return winsec.DACLHandle(h, windows.SE_KERNEL_OBJECT)
}
