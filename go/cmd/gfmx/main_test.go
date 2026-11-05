package main

import (
	"bytes"
	"os"
	"testing"
)

// Regression: a TRUSTED CERTIFICATE block (OpenSSL X509_AUX) must give the
// same certificate as the plain PEM, without the trust settings that follow it.
func TestTrustedPEM(t *testing.T) {
	read := func(n string) [][]byte {
		b, err := os.ReadFile("../../../tests/data/" + n)
		if err != nil {
			t.Fatal(err)
		}
		d, err := loadBytes(b)
		if err != nil || len(d) != 1 {
			t.Fatalf("%s: %v %d", n, err, len(d))
		}
		return d
	}
	if p, tr := read("ca.pem"), read("ca_trusted.pem"); !bytes.Equal(p[0], tr[0]) {
		t.Fatalf("trusted block not trimmed: %d vs %d bytes", len(p[0]), len(tr[0]))
	}
}
