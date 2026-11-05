package model

import (
	"errors"
	"testing"
)

func TestNormalizeCertKeyType(t *testing.T) {
	for in, want := range map[string]string{
		"":        CertKeyTypeRSA2048, // requests and backups from before #364
		"rsa2048": CertKeyTypeRSA2048,
		"EC256":   CertKeyTypeEC256,
		" ec384 ": CertKeyTypeEC384,
	} {
		got, err := NormalizeCertKeyType(in)
		if err != nil || got != want {
			t.Errorf("NormalizeCertKeyType(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ec521", "rsa4096", "ecdsa"} {
		if _, err := NormalizeCertKeyType(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("NormalizeCertKeyType(%q) err = %v, want ErrInvalidInput", in, err)
		}
	}
}
