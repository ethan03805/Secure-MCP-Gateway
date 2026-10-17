package adapter_test

import (
	"encoding/pem"
	"net"
	"net/http/httptest"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

type auditEvent = audit.Event

func netListenUnix(path string) (net.Listener, error) { return net.Listen("unix", path) }

// pemCert returns the test server's certificate as a PEM trust root.
func pemCert(s *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}
