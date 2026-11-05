package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve answers TLS handshakes on a local port with cfg until the test ends.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// An old appliance that only speaks TLS 1.0 with RSA key exchange, which Go clients no
// longer offer by default.
func TestFetchLegacyServer(t *testing.T) {
	cert := selfSigned(t, "legacy")
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS12} {
		addr := serve(t, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   v, MaxVersion: v,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		})
		der, err := fetchLeaf(addr, "", 5*time.Second)
		if err != nil {
			t.Fatalf("version %x: %v", v, err)
		}
		if !bytes.Equal(der, cert.Certificate[0]) {
			t.Fatalf("version %x: wrong certificate", v)
		}
	}
}

// An IP address sends no SNI and gets the default certificate; --sni selects another.
func TestFetchSNI(t *testing.T) {
	def, alt := selfSigned(t, "default"), selfSigned(t, "alt.test")
	addr := serve(t, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "alt.test" {
			return &alt, nil
		}
		return &def, nil
	}})
	for sni, want := range map[string]tls.Certificate{"": def, "alt.test": alt} {
		der, err := fetchLeaf(addr, sni, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(der, want.Certificate[0]) {
			t.Errorf("sni %q: wrong certificate", sni)
		}
	}
}
