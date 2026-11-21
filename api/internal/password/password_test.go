package password

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

var (
	pepperA = []byte(strings.Repeat("a", 32) + "-pepper-a")
	pepperB = []byte(strings.Repeat("b", 32) + "-pepper-b")
)

// use installs cfg for one test and restores plain bcrypt afterwards.
func use(t *testing.T, cfg Config) {
	t.Helper()
	Configure(cfg)
	t.Cleanup(func() { Configure(Config{}) })
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return h
}

func TestWithoutPepperHashIsPlainBcrypt(t *testing.T) {
	use(t, Config{})
	h := mustHash(t, "correct horse battery")
	if strings.HasPrefix(h, PepperedPrefix) {
		t.Fatalf("hash is peppered with no pepper configured: %q", h)
	}
	// Byte-for-byte what NPG stored before this package: plain bcrypt that the
	// library itself accepts, at DefaultCost.
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("correct horse battery")); err != nil {
		t.Fatalf("plain hash does not verify with bcrypt: %v", err)
	}
	if cost, _ := bcrypt.Cost([]byte(h)); cost != bcrypt.DefaultCost {
		t.Fatalf("cost = %d, want %d", cost, bcrypt.DefaultCost)
	}
	if ok, rehash := Verify(h, "correct horse battery"); !ok || rehash {
		t.Fatalf("Verify = (%v, %v), want (true, false)", ok, rehash)
	}
	if ok, _ := Verify(h, "wrong"); ok {
		t.Fatal("wrong password verified")
	}
}

func TestWithoutPepperOver72BytesIsRefused(t *testing.T) {
	use(t, Config{})
	if _, err := Hash(strings.Repeat("x", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Hash(73 bytes) err = %v, want ErrPasswordTooLong", err)
	}
}

func TestPepperedRoundTrip(t *testing.T) {
	use(t, Config{Pepper: pepperA})
	h := mustHash(t, "correct horse battery")
	if !strings.HasPrefix(h, PepperedPrefix) {
		t.Fatalf("hash is not peppered: %q", h)
	}
	if len(h) > 255 {
		t.Fatalf("hash is %d bytes, over users.password_hash's 255", len(h))
	}
	// The stored bcrypt must not be a hash of the password itself.
	if bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(h, PepperedPrefix)), []byte("correct horse battery")) == nil {
		t.Fatal("peppered hash verifies as plain bcrypt of the password")
	}
	if ok, rehash := Verify(h, "correct horse battery"); !ok || rehash {
		t.Fatalf("Verify = (%v, %v), want (true, false)", ok, rehash)
	}
	if ok, _ := Verify(h, "correct horse batterY"); ok {
		t.Fatal("wrong password verified")
	}
}

func TestPlainHashNeedsRehashOncePepperIsSet(t *testing.T) {
	use(t, Config{})
	plain := mustHash(t, "an existing password")

	use(t, Config{Pepper: pepperA})
	ok, rehash := Verify(plain, "an existing password")
	if !ok || !rehash {
		t.Fatalf("Verify(plain) = (%v, %v), want (true, true)", ok, rehash)
	}
	if ok, rehash := Verify(plain, "not it"); ok || rehash {
		t.Fatalf("wrong password: Verify = (%v, %v), want (false, false)", ok, rehash)
	}
	upgraded := mustHash(t, "an existing password")
	if ok, rehash := Verify(upgraded, "an existing password"); !ok || rehash {
		t.Fatalf("Verify(upgraded) = (%v, %v), want (true, false)", ok, rehash)
	}
}

func TestPreviousPepperVerifiesAndNeedsRehash(t *testing.T) {
	use(t, Config{Pepper: pepperA})
	old := mustHash(t, "rotate me please")

	use(t, Config{Pepper: pepperB, Previous: pepperA})
	ok, rehash := Verify(old, "rotate me please")
	if !ok || !rehash {
		t.Fatalf("Verify(old pepper) = (%v, %v), want (true, true)", ok, rehash)
	}
	if ok, _ := Verify(old, "wrong"); ok {
		t.Fatal("wrong password verified against the previous pepper")
	}
	fresh := mustHash(t, "rotate me please")
	if ok, rehash := Verify(fresh, "rotate me please"); !ok || rehash {
		t.Fatalf("Verify(new pepper) = (%v, %v), want (true, false)", ok, rehash)
	}
}

func TestWrongPepperFails(t *testing.T) {
	use(t, Config{Pepper: pepperA})
	h := mustHash(t, "correct horse battery")

	use(t, Config{Pepper: pepperB})
	if ok, _ := Verify(h, "correct horse battery"); ok {
		t.Fatal("hash made with pepper A verified under pepper B")
	}
}

func TestPepperedHashWithoutPepperFailsClosed(t *testing.T) {
	use(t, Config{Pepper: pepperA})
	h := mustHash(t, "correct horse battery")

	use(t, Config{})
	if ok, rehash := Verify(h, "correct horse battery"); ok || rehash {
		t.Fatalf("Verify with the pepper missing = (%v, %v), want (false, false)", ok, rehash)
	}
}

func TestPepperedPathHasNo72ByteLimit(t *testing.T) {
	use(t, Config{Pepper: pepperA})
	long := strings.Repeat("x", 100)
	h := mustHash(t, long)
	if ok, _ := Verify(h, long); !ok {
		t.Fatal("100-byte password did not verify")
	}
	// bcrypt alone would only honour the first 72 bytes; the HMAC sees them all.
	if ok, _ := Verify(h, strings.Repeat("x", 72)+strings.Repeat("y", 28)); ok {
		t.Fatal("password differing after byte 72 verified")
	}
}

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestLoadFromEnv(t *testing.T) {
	long := strings.Repeat("p", 64)
	other := strings.Repeat("q", 64)
	dir := t.TempDir()
	file := filepath.Join(dir, "pepper")
	if err := os.WriteFile(file, []byte(long+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		vars    map[string]string
		want    Config
		wantErr string
	}{
		{name: "unset keeps plain bcrypt", vars: nil, want: Config{}},
		{name: "direct", vars: map[string]string{EnvPepper: long}, want: Config{Pepper: []byte(long)}},
		{name: "file trims the newline", vars: map[string]string{EnvPepperFile: file}, want: Config{Pepper: []byte(long)}},
		{name: "rotation", vars: map[string]string{EnvPepper: other, EnvPreviousPepperFile: file}, want: Config{Pepper: []byte(other), Previous: []byte(long)}},
		{name: "too short", vars: map[string]string{EnvPepper: "short-pepper"}, wantErr: "at least 32 bytes"},
		{name: "both forms", vars: map[string]string{EnvPepper: long, EnvPepperFile: file}, wantErr: "both"},
		{name: "missing file", vars: map[string]string{EnvPepperFile: filepath.Join(dir, "nope")}, wantErr: "cannot read"},
		{name: "previous without current", vars: map[string]string{EnvPreviousPepper: long}, wantErr: "is not"},
		{name: "previous equals current", vars: map[string]string{EnvPepper: long, EnvPreviousPepper: long}, wantErr: "same as"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFromEnv(env(tc.vars), os.ReadFile)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				// The pepper never appears in an error.
				if strings.Contains(err.Error(), long) || strings.Contains(err.Error(), "short-pepper") {
					t.Fatalf("error leaks the pepper: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if string(got.Pepper) != string(tc.want.Pepper) || string(got.Previous) != string(tc.want.Previous) {
				t.Fatalf("got pepper=%q previous=%q, want pepper=%q previous=%q",
					got.Pepper, got.Previous, tc.want.Pepper, tc.want.Previous)
			}
		})
	}
}

func TestConfigureCopiesThePepper(t *testing.T) {
	p := append([]byte(nil), pepperA...)
	use(t, Config{Pepper: p})
	h := mustHash(t, "correct horse battery")
	p[0] ^= 0xff // the caller's slice changing must not change the installed pepper
	if ok, _ := Verify(h, "correct horse battery"); !ok {
		t.Fatal("Configure kept a reference to the caller's slice")
	}
}
