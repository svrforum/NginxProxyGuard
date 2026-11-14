// Package password hashes and verifies account passwords, optionally with a
// pepper: a secret kept outside the database and mixed into every hash.
//
// Without a pepper, a hash is plain bcrypt, exactly as NPG has always stored
// it. bcrypt already salts each hash, so a leaked users table cannot be
// attacked with precomputed tables, but every hash in it can still be guessed
// at offline. With a pepper, the stored hash is
//
//	$npgp1$ + bcrypt(base64(HMAC-SHA256(pepper, password)))
//
// and a copy of the database, a dump of it, or a disk snapshot is not enough
// to test a single guess: the attacker also needs the pepper, which lives only
// in the api container's environment or a secret file.
//
// Hashes written before a pepper was configured keep working. They verify as
// plain bcrypt and report needsRehash, so the caller re-encodes them with the
// pepper the next time the password is presented. NPG_PASSWORD_PEPPER_PREVIOUS
// does the same for a pepper being rotated out.
package password

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

// PepperedPrefix marks a hash whose bcrypt input was the HMAC of the password
// under the pepper. The digit versions the construction, so a later change to
// it can live next to hashes written by this one.
const PepperedPrefix = "$npgp1$"

// MinPepperLength is the shortest pepper accepted. The pepper is the whole
// point of the scheme, so it must be a random secret, not a word: 32 bytes is
// what `openssl rand -hex 32` prints in 64 characters, comfortably above it.
const MinPepperLength = 32

// Environment variables that configure the pepper. Each value can instead come
// from a file (a Docker or Kubernetes secret) named by the _FILE variant.
const (
	EnvPepper             = "NPG_PASSWORD_PEPPER"
	EnvPepperFile         = "NPG_PASSWORD_PEPPER_FILE"
	EnvPreviousPepper     = "NPG_PASSWORD_PEPPER_PREVIOUS"
	EnvPreviousPepperFile = "NPG_PASSWORD_PEPPER_PREVIOUS_FILE"
)

// ErrPasswordTooLong is bcrypt's 72-byte input limit. It applies only while no
// pepper is configured: the peppered path feeds bcrypt a fixed-length HMAC, so
// any password length works there.
var ErrPasswordTooLong = bcrypt.ErrPasswordTooLong

// Config holds the peppers. A zero Config is plain bcrypt.
type Config struct {
	// Pepper is used for every new hash and tried first on verify.
	Pepper []byte
	// Previous is a pepper being rotated out. Hashes made with it still
	// verify, and report needsRehash so they move to Pepper.
	Previous []byte
}

// Enabled reports whether new hashes are peppered.
func (c Config) Enabled() bool { return len(c.Pepper) > 0 }

var (
	current atomic.Pointer[Config]
	// missingPepperOnce limits the "peppered hash but no pepper" error to one
	// log line per process, not one per login attempt.
	missingPepperOnce sync.Once
)

// Configure installs cfg for Hash and Verify. It is called once at startup,
// before any request is served; tests call it to switch peppers.
func Configure(cfg Config) {
	c := Config{
		Pepper:   append([]byte(nil), cfg.Pepper...),
		Previous: append([]byte(nil), cfg.Previous...),
	}
	current.Store(&c)
}

func config() Config {
	if c := current.Load(); c != nil {
		return *c
	}
	return Config{}
}

// Enabled reports whether the installed configuration peppers new hashes.
func Enabled() bool { return config().Enabled() }

// LoadFromEnv reads the pepper configuration from the environment. Every
// variable unset yields a zero Config, which keeps today's plain bcrypt. A
// pepper that is set but too short, a value given both directly and as a file,
// or a previous pepper without a current one is an error: the caller should
// refuse to start rather than run with a weaker or half-applied setup.
func LoadFromEnv() (Config, error) {
	return loadFromEnv(os.Getenv, os.ReadFile)
}

// ConfigureFromEnv loads the configuration with LoadFromEnv and installs it.
// It logs whether peppering is on, never the pepper itself.
func ConfigureFromEnv() error {
	cfg, err := LoadFromEnv()
	if err != nil {
		return err
	}
	Configure(cfg)
	switch {
	case len(cfg.Previous) > 0:
		log.Printf("[Password] %s is set: new password hashes are peppered; hashes made with %s move to the new pepper at each account's next sign-in", EnvPepper, EnvPreviousPepper)
	case cfg.Enabled():
		log.Printf("[Password] %s is set: new password hashes are peppered; existing plain bcrypt hashes are re-encoded at each account's next sign-in", EnvPepper)
	}
	return nil
}

func loadFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	pepper, err := secretFromEnv(EnvPepper, EnvPepperFile, getenv, readFile)
	if err != nil {
		return Config{}, err
	}
	previous, err := secretFromEnv(EnvPreviousPepper, EnvPreviousPepperFile, getenv, readFile)
	if err != nil {
		return Config{}, err
	}
	if len(previous) > 0 && len(pepper) == 0 {
		return Config{}, fmt.Errorf("%s is set but %s is not: set the new pepper too, or remove the previous one", EnvPreviousPepper, EnvPepper)
	}
	if len(previous) > 0 && hmac.Equal(previous, pepper) {
		return Config{}, fmt.Errorf("%s is the same as %s: remove it, or set %s to the new pepper", EnvPreviousPepper, EnvPepper, EnvPepper)
	}
	return Config{Pepper: pepper, Previous: previous}, nil
}

// secretFromEnv reads one pepper from name or nameFile. The file form trims
// trailing newlines, which editors and `echo` add; the pepper itself must not
// end in one.
func secretFromEnv(name, nameFile string, getenv func(string) string, readFile func(string) ([]byte, error)) ([]byte, error) {
	direct := getenv(name)
	path := strings.TrimSpace(getenv(nameFile))
	if direct != "" && path != "" {
		return nil, fmt.Errorf("both %s and %s are set: use one", name, nameFile)
	}
	var value string
	switch {
	case direct != "":
		value = direct
	case path != "":
		b, err := readFile(path)
		if err != nil {
			// The path is the operator's own setting; the contents are never
			// part of the message.
			return nil, fmt.Errorf("%s: cannot read %s: %w", nameFile, path, err)
		}
		value = strings.TrimRight(string(b), "\r\n")
	default:
		return nil, nil
	}
	if len(value) < MinPepperLength {
		return nil, fmt.Errorf("%s must be at least %d bytes (it is %d); generate one with `openssl rand -hex 32`", name, MinPepperLength, len(value))
	}
	return []byte(value), nil
}

// prehash is the bcrypt input for a peppered hash. HMAC binds the pepper to the
// password; base64 keeps the 32-byte digest free of the NUL bytes bcrypt
// mishandles and, at 43 characters, under its 72-byte limit whatever the
// password's length.
func prehash(pepper []byte, plaintext string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(plaintext))
	sum := mac.Sum(nil)
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(sum)))
	base64.RawStdEncoding.Encode(out, sum)
	return out
}

// Hash returns the stored form of plaintext under the installed configuration:
// peppered when a pepper is set, plain bcrypt otherwise. Both use
// bcrypt.DefaultCost. Without a pepper, a password over 72 bytes is refused
// with ErrPasswordTooLong, as bcrypt itself does.
func Hash(plaintext string) (string, error) {
	cfg := config()
	if !cfg.Enabled() {
		h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		return string(h), nil
	}
	h, err := bcrypt.GenerateFromPassword(prehash(cfg.Pepper, plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return PepperedPrefix + string(h), nil
}

// Verify reports whether plaintext matches stored. needsRehash is true when the
// match succeeded but stored is not in the form Hash would write now: a plain
// bcrypt hash while a pepper is configured, or a hash made with the previous
// pepper. The caller then stores Hash(plaintext) in its place.
//
// A peppered hash with no pepper configured never matches. That is the
// fail-closed answer to a pepper that went missing from the environment, and
// it is logged once so the operator can tell it from a wrong password.
func Verify(stored, plaintext string) (ok, needsRehash bool) {
	cfg := config()
	if rest, peppered := strings.CutPrefix(stored, PepperedPrefix); peppered {
		if !cfg.Enabled() {
			missingPepperOnce.Do(func() {
				log.Printf("[Password] ERROR: a stored password hash is peppered but %s is not set, so that account cannot sign in. Restore the pepper the hash was made with (or reset the password with the reset-password command).", EnvPepper)
			})
			return false, false
		}
		if bcrypt.CompareHashAndPassword([]byte(rest), prehash(cfg.Pepper, plaintext)) == nil {
			return true, false
		}
		if len(cfg.Previous) > 0 && bcrypt.CompareHashAndPassword([]byte(rest), prehash(cfg.Previous, plaintext)) == nil {
			return true, true
		}
		return false, false
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(plaintext)) != nil {
		return false, false
	}
	return true, cfg.Enabled()
}
