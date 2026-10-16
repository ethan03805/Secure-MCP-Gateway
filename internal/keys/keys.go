// Package keys is the slice of the Key & Trust Anchor Manager (E-22) the
// Gateway needs today: a local server CA with a certificate for the harness
// and admin listeners (FR-7.7), the Ed25519 evidence-signing key (FR-7.8),
// the local operator token of the control API and Argon2id password hashing
// (CP-28). Keys are files with mode 0600 under the state directory; TPM
// sealing and passphrase encryption (FR-7.9) are not yet implemented.
//
// Certificate lifetimes: the server CA is valid for CALifetime (two years)
// and is name-constrained to the loopback names, so a leaked CA key cannot
// mint certificates for any public name. Leaf certificates are valid for
// LeafLifetime (397 days, the CA/Browser Forum ceiling). RotateIfDue
// reissues the leaf from the existing CA when it is within RotateBefore of
// expiry and reports when the CA itself needs replacing; smcpd calls it at
// startup. Replacing the CA is an operator action (rerun Ensure after moving
// the old tls directory aside) because every client trust store must be
// updated with it.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// Layout under the state directory.
const (
	CACertFile       = "tls/ca.crt"
	CAKeyFile        = "tls/ca.key"
	ServerCertFile   = "tls/server.crt"
	ServerKeyFile    = "tls/server.key"
	EvidenceKeyFile  = "keys/evidence.key"
	EvidencePubFile  = "keys/evidence.pub"
	AdminTokenFile   = "keys/admin.token"
	EvidenceKeyBytes = ed25519.SeedSize
)

// Certificate lifetimes.
const (
	CALifetime   = 2 * 365 * 24 * time.Hour
	LeafLifetime = 397 * 24 * time.Hour
	RotateBefore = 30 * 24 * time.Hour
)

// loopbackIPs are always permitted by the CA name constraints.
var loopbackIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

// Ensure creates any missing key material under stateDir. names are the
// listener host names or IP literals the leaf certificate must cover in
// addition to localhost, 127.0.0.1 and ::1. Existing files are kept.
func Ensure(stateDir string, names ...string) error {
	for _, d := range []string{"tls", "keys"} {
		if err := os.MkdirAll(filepath.Join(stateDir, d), 0o700); err != nil {
			return err
		}
	}
	if !exists(filepath.Join(stateDir, CAKeyFile)) || !exists(filepath.Join(stateDir, ServerKeyFile)) {
		if err := generateTLS(stateDir, names); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}
	if !exists(filepath.Join(stateDir, EvidenceKeyFile)) {
		if err := generateEvidenceKey(stateDir); err != nil {
			return fmt.Errorf("evidence key: %w", err)
		}
	}
	if !exists(filepath.Join(stateDir, AdminTokenFile)) {
		if err := os.WriteFile(filepath.Join(stateDir, AdminTokenFile), []byte(ids.Secret()+"\n"), 0o600); err != nil {
			return fmt.Errorf("admin token: %w", err)
		}
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// leafNames splits the listener names into DNS names and IPs, always
// including the loopback names.
func leafNames(names []string) (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	ips = append(ips, loopbackIPs...)
	for _, n := range names {
		n = strings.Trim(n, "[]")
		if n == "" {
			continue
		}
		if ip := net.ParseIP(n); ip != nil {
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append(ips, ip)
			}
		} else if !slices.Contains(dns, n) {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

func generateTLS(stateDir string, names []string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dns, ips := leafNames(names)
	var ipNets []*net.IPNet
	for _, ip := range ips {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		ipNets = append(ipNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Secure MCP Gateway server CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CALifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		// The CA can only vouch for the loopback listener names.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         dns,
		PermittedIPRanges:           ipNets,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, CACertFile), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, CAKeyFile), "EC PRIVATE KEY", caKeyDER, 0o600); err != nil {
		return err
	}
	return issueLeaf(stateDir, caCert, caKey, dns, ips)
}

func issueLeaf(stateDir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dns []string, ips []net.IP) error {
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	notAfter := now.Add(LeafLifetime)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "Secure MCP Gateway listener"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, ServerKeyFile), "EC PRIVATE KEY", srvKeyDER, 0o600); err != nil {
		return err
	}
	return writePEM(filepath.Join(stateDir, ServerCertFile), "CERTIFICATE", srvDER, 0o644)
}

// TLSStatus describes the listener certificates.
type TLSStatus struct {
	CANotAfter   time.Time
	LeafNotAfter time.Time
	CADue        bool // the CA expires within RotateBefore; operator action needed
	LeafRotated  bool // RotateIfDue reissued the leaf
}

// RotateIfDue reissues the leaf certificate from the existing CA when it
// expires within RotateBefore or does not cover names, and reports the CA
// state. It never replaces the CA.
func RotateIfDue(stateDir string, now time.Time, names ...string) (TLSStatus, error) {
	var st TLSStatus
	caCert, err := loadCert(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return st, err
	}
	leaf, err := loadCert(filepath.Join(stateDir, ServerCertFile))
	if err != nil {
		return st, err
	}
	st.CANotAfter, st.LeafNotAfter = caCert.NotAfter, leaf.NotAfter
	st.CADue = now.Add(RotateBefore).After(caCert.NotAfter)
	dns, ips := leafNames(names)
	covers := true
	for _, d := range dns {
		if leaf.VerifyHostname(d) != nil {
			covers = false
		}
	}
	for _, ip := range ips {
		if leaf.VerifyHostname(ip.String()) != nil {
			covers = false
		}
	}
	if covers && !now.Add(RotateBefore).After(leaf.NotAfter) {
		return st, nil
	}
	if st.CADue {
		return st, errors.New("server CA expires within the rotation window; replace the CA")
	}
	b, err := os.ReadFile(filepath.Join(stateDir, CAKeyFile))
	if err != nil {
		return st, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return st, errors.New("CA key is not PEM")
	}
	caKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return st, err
	}
	if err := issueLeaf(stateDir, caCert, caKey, dns, ips); err != nil {
		return st, err
	}
	leaf, err = loadCert(filepath.Join(stateDir, ServerCertFile))
	if err != nil {
		return st, err
	}
	st.LeafNotAfter, st.LeafRotated = leaf.NotAfter, true
	return st, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// writePEM writes atomically: a temporary file in the same directory is
// renamed over the target, so a crash never leaves a truncated key.
func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// WriteFileAtomic writes data to a temporary file, syncs it and renames it
// over path.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func generateEvidenceKey(stateDir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := hex.EncodeToString(priv.Seed())
	if err := WriteFileAtomic(filepath.Join(stateDir, EvidenceKeyFile), []byte(seed+"\n"), 0o600); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(stateDir, EvidencePubFile), []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// LoadEvidenceKey returns the Ed25519 signing key from the state directory.
func LoadEvidenceKey(stateDir string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, EvidenceKeyFile))
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("evidence key file is not a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadEvidencePublicKey returns the verification key from the state directory.
func LoadEvidencePublicKey(stateDir string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, EvidencePubFile))
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("evidence public key file is not a 32-byte hex key")
	}
	return ed25519.PublicKey(pub), nil
}

// LoadAdminToken returns the local operator token of the control API. The
// file is readable only by the account that runs the Gateway; holding it is
// equivalent to administrator access, like holding the CA key.
func LoadAdminToken(stateDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, AdminTokenFile))
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if len(tok) < 43 {
		return "", errors.New("admin token file is too short")
	}
	return tok, nil
}
