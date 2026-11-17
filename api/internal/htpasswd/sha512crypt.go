// Package htpasswd writes the password hashes of the basic auth accounts in
// access lists (#387), in the form nginx's auth_basic_user_file reads.
//
// The hash is SHA-512 crypt ("$6$", Drepper's SHA-crypt). nginx hands it to
// the C library's crypt(), which in the nginx image (musl) knows it. nginx
// checks the password on every request that carries one, in the worker, so
// the cost matters: bcrypt at a useful cost holds a worker for tens of
// milliseconds per request, SHA-512 crypt at its default 5000 rounds for
// about one.
package htpasswd

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"strings"
)

const (
	itoa64     = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	saltLen    = 16
	defRounds  = 5000
	hashPrefix = "$6$"
)

// Hash returns the SHA-512 crypt hash of password with a random salt and the
// default rounds, e.g. "$6$<salt>$<hash>".
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	random := make([]byte, saltLen)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("htpasswd: read random salt: %w", err)
	}
	for i, b := range random {
		salt[i] = itoa64[int(b)%len(itoa64)]
	}
	return sha512Crypt([]byte(password), salt), nil
}

// IsHash reports whether s has the shape Hash produces, so a value read back
// from a backup can be told from anything else before it reaches a file
// nginx reads line by line.
func IsHash(s string) bool {
	rest, ok := strings.CutPrefix(s, hashPrefix)
	if !ok {
		return false
	}
	salt, sum, ok := strings.Cut(rest, "$")
	if !ok || salt == "" || len(salt) > saltLen || len(sum) != 86 {
		return false
	}
	for _, c := range salt + sum {
		if !strings.ContainsRune(itoa64, c) {
			return false
		}
	}
	return true
}

// sha512Crypt is SHA-crypt with SHA-512 at the default rounds, which the
// output does not name ("$6$salt$hash"), as glibc and musl write it.
func sha512Crypt(key, salt []byte) string {
	// Digest B: key, salt, key.
	b := sha512.New()
	b.Write(key)
	b.Write(salt)
	b.Write(key)
	sumB := b.Sum(nil)

	// Digest A: key, salt, then B for each full and the partial 64 bytes of
	// the key, then B or the key for each bit of the key's length.
	a := sha512.New()
	a.Write(key)
	a.Write(salt)
	n := len(key)
	for ; n > 64; n -= 64 {
		a.Write(sumB)
	}
	a.Write(sumB[:n])
	for n = len(key); n > 0; n >>= 1 {
		if n&1 != 0 {
			a.Write(sumB)
		} else {
			a.Write(key)
		}
	}
	sumA := a.Sum(nil)

	// P: the digest of the key repeated once per key byte, cut to the key's length.
	dp := sha512.New()
	for range key {
		dp.Write(key)
	}
	p := repeatTo(dp.Sum(nil), len(key))

	// S: the digest of the salt repeated 16 + A[0] times, cut to the salt's length.
	ds := sha512.New()
	for i := 0; i < 16+int(sumA[0]); i++ {
		ds.Write(salt)
	}
	s := repeatTo(ds.Sum(nil), len(salt))

	for i := 0; i < defRounds; i++ {
		c := sha512.New()
		if i&1 != 0 {
			c.Write(p)
		} else {
			c.Write(sumA)
		}
		if i%3 != 0 {
			c.Write(s)
		}
		if i%7 != 0 {
			c.Write(p)
		}
		if i&1 != 0 {
			c.Write(sumA)
		} else {
			c.Write(p)
		}
		sumA = c.Sum(sumA[:0])
	}

	var out strings.Builder
	out.WriteString(hashPrefix)
	out.Write(salt)
	out.WriteByte('$')
	for _, t := range [...][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4},
		{47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51},
		{31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
		{15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
		{62, 20, 41},
	} {
		b64From24(&out, sumA[t[0]], sumA[t[1]], sumA[t[2]], 4)
	}
	b64From24(&out, 0, 0, sumA[63], 2)
	return out.String()
}

func repeatTo(digest []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out)+len(digest) <= n {
		out = append(out, digest...)
	}
	return append(out, digest[:n-len(out)]...)
}

func b64From24(out *strings.Builder, b2, b1, b0 byte, n int) {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for ; n > 0; n-- {
		out.WriteByte(itoa64[w&0x3f])
		w >>= 6
	}
}
