package filters

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash/maphash"
	"net/url"
	"strings"
	"sync"
	"unicode"
)

// FingerprintWindow is the FR-6.10 substring length.
const FingerprintWindow = 12

// FingerprintSet holds non-reversible detectors for registered secret
// values (FR-6.10, ARCH §8.5): a keyed HMAC-SHA-256 of each value's full
// form and of every 12-character substring of its raw, Base64, hex and
// URL-encoded forms. Plaintext is never retained. A process-local seeded
// 64-bit hash of each window is kept as a prefilter so that scanning a
// large result costs one cheap hash per byte; a prefilter hit is confirmed
// with the HMAC. The keys are random per process and never leave memory.
//
// The Secret Broker (E-20) registers values here when it delivers a
// secret; until it exists, nothing is registered and the set matches
// nothing.
type FingerprintSet struct {
	mu      sync.RWMutex
	key     []byte
	seed    maphash.Seed
	pre     map[uint64]struct{}
	windows map[[32]byte]string // HMAC of a window -> secret reference
	full    map[[32]byte]string // HMAC of a whole short value -> reference
}

// NewFingerprintSet returns an empty set with fresh keys.
func NewFingerprintSet() *FingerprintSet {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return &FingerprintSet{key: key, seed: maphash.MakeSeed(), pre: map[uint64]struct{}{},
		windows: map[[32]byte]string{}, full: map[[32]byte]string{}}
}

func (f *FingerprintSet) mac(s string) [32]byte {
	m := hmac.New(sha256.New, f.key)
	m.Write([]byte(s))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// encodedForms are the forms FR-6.10 names.
func encodedForms(v string) []string {
	return []string{v,
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawStdEncoding.EncodeToString([]byte(v)),
		base64.URLEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
		hex.EncodeToString([]byte(v)),
		strings.ToUpper(hex.EncodeToString([]byte(v))),
		url.QueryEscape(v),
		url.PathEscape(v),
	}
}

// Register adds the fingerprints of value under ref (a secret reference,
// never the value). Values shorter than the window match only as a whole
// token.
func (f *FingerprintSet) Register(ref, value string) {
	if value == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, form := range encodedForms(value) {
		f.full[f.mac(form)] = ref
		if len(form) < FingerprintWindow {
			continue
		}
		for i := 0; i+FingerprintWindow <= len(form); i++ {
			w := form[i : i+FingerprintWindow]
			f.pre[maphash.String(f.seed, w)] = struct{}{}
			f.windows[f.mac(w)] = ref
		}
	}
}

// Len reports the number of window fingerprints held.
func (f *FingerprintSet) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.windows) + len(f.full)
}

// Match reports whether s contains a registered secret fragment, and which
// reference matched.
func (f *FingerprintSet) Match(s string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.full) == 0 {
		return "", false
	}
	for i := 0; i+FingerprintWindow <= len(s); i++ {
		w := s[i : i+FingerprintWindow]
		if _, hit := f.pre[maphash.String(f.seed, w)]; !hit {
			continue
		}
		if ref, ok := f.windows[f.mac(w)]; ok {
			return ref, true
		}
	}
	for _, tok := range strings.FieldsFunc(s, func(c rune) bool {
		return !(unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune("-_.+/=%~!@#$^&*", c))
	}) {
		if ref, ok := f.full[f.mac(tok)]; ok {
			return ref, true
		}
	}
	return "", false
}
