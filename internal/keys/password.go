package keys

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// CP-28 Argon2id parameters.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 1
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// Upper bounds on parameters read from a stored hash, so that a crafted
// configuration entry cannot make one verification exhaust memory or CPU.
const (
	maxMemoryKiB = 256 * 1024
	maxTime      = 10
	maxThreads   = 8
	maxKeyLen    = 64
)

// HashPassword returns a PHC-formatted Argon2id hash of the password using the
// CP-28 parameters.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the PHC-formatted hash.
// Hashes with parameters above the built-in bounds never match.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	if mem == 0 || mem > maxMemoryKiB || t == 0 || t > maxTime || p == 0 || p > maxThreads {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	keyLen := len(want)
	if keyLen == 0 || keyLen > maxKeyLen {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(keyLen))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummy     string
)

// DummyHash returns a valid hash of a random password with the CP-28
// parameters. Verifying against it when an account is unknown makes the
// unknown-account path cost the same as a wrong password.
func DummyHash() string {
	dummyOnce.Do(func() {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("crypto/rand: " + err.Error())
		}
		h, err := HashPassword(base64.RawStdEncoding.EncodeToString(b[:]))
		if err != nil {
			panic(err)
		}
		dummy = h
	})
	return dummy
}
