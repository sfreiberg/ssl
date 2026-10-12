package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSLVersionS(t *testing.T) {
	tests := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
		0:                "Unknown",
	}

	for ver, want := range tests {
		if got := sslVersionS(ver); got != want {
			t.Errorf("sslVersionS(%#x) = %q, want %q", ver, got, want)
		}
	}
}

func TestCipherS(t *testing.T) {
	tests := map[uint16]string{
		tls.TLS_AES_128_GCM_SHA256:                  "AES_128_GCM/SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE_ECDSA/AES_256_GCM/SHA384",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "RSA/AES_128_CBC/SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE_RSA/AES_128_GCM/SHA256",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "ECDHE_RSA/CHACHA20/POLY1305/SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "ECDHE_ECDSA/CHACHA20/POLY1305/SHA256",
		0: "Unknown",
	}

	for cipher, want := range tests {
		if got := cipherS(cipher); got != want {
			t.Errorf("cipherS(%#x) = %q, want %q", cipher, got, want)
		}
	}
}

func TestExpired(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	tests := []struct {
		name       string
		start, end time.Time
		want       bool
	}{
		{"valid", now.Add(-day), now.Add(day), false},
		{"not yet valid", now.Add(day), now.Add(2 * day), true},
		{"expired", now.Add(-2 * day), now.Add(-day), true},
	}

	for _, tt := range tests {
		if got := expired(tt.start, tt.end); got != tt.want {
			t.Errorf("%s: expired() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCertStartEnd(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	certs := []*x509.Certificate{
		{NotBefore: base, NotAfter: base.AddDate(1, 0, 0)},
		{NotBefore: base.AddDate(0, 1, 0), NotAfter: base.AddDate(0, 6, 0)},
		{NotBefore: base.AddDate(0, -1, 0), NotAfter: base.AddDate(2, 0, 0)},
	}

	// The chain is only valid from the latest start to the earliest end.
	if got, want := certStart(certs), base.AddDate(0, 1, 0); !got.Equal(want) {
		t.Errorf("certStart() = %v, want %v", got, want)
	}
	if got, want := certEnd(certs), base.AddDate(0, 6, 0); !got.Equal(want) {
		t.Errorf("certEnd() = %v, want %v", got, want)
	}

	if !certStart(nil).IsZero() || !certEnd(nil).IsZero() {
		t.Error("certStart/certEnd with no certs should return the zero time")
	}
	if got := certStart(certs[:1]); !got.Equal(base) {
		t.Errorf("certStart() single cert = %v, want %v", got, base)
	}
	if got, want := certEnd(certs[:1]), base.AddDate(1, 0, 0); !got.Equal(want) {
		t.Errorf("certEnd() single cert = %v, want %v", got, want)
	}
}

func TestHexEncode(t *testing.T) {
	tests := map[string][]byte{
		"01 AB FF": {0x01, 0xab, 0xff},
		"0A":       {0x0a},
		"":         {},
	}

	for want, b := range tests {
		if got := hexEncode(b); got != want {
			t.Errorf("hexEncode(%v) = %q, want %q", b, got, want)
		}
	}
}

func TestSerialNumberS(t *testing.T) {
	tests := map[int64]string{
		0x0a0b0c: "0A 0B 0C",
		0:        "00",
	}

	for serial, want := range tests {
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial)}
		if got := serialNumberS(cert); got != want {
			t.Errorf("serialNumberS(%#x) = %q, want %q", serial, got, want)
		}
	}
}

func TestSHA256Fingerprint(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate")}
	sum := sha256.Sum256(cert.Raw)

	got := sha256Fingerprint(cert)
	if want := hexEncode(sum[:]); got != want {
		t.Errorf("sha256Fingerprint() = %q, want %q", got, want)
	}
	if len(strings.Fields(got)) != sha256.Size {
		t.Errorf("sha256Fingerprint() = %q, want %d space separated bytes", got, sha256.Size)
	}
}

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExec(t *testing.T) {
	srv := newTLSServer(t)
	addr := srv.Listener.Addr().String()
	cert := srv.Certificate()

	res := exec(addr)
	if res.Error != nil {
		t.Fatalf("exec(%q) error: %v", addr, res.Error)
	}

	if res.Address != addr {
		t.Errorf("Address = %q, want %q", res.Address, addr)
	}
	if res.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want %q", res.Version, "TLS 1.3")
	}
	if res.Cipher == "Unknown" {
		t.Error("Cipher = Unknown, want a known cipher suite")
	}
	if res.Expired {
		t.Error("Expired = true, want false")
	}
	// The httptest certificate is valid for 127.0.0.1 and example.com.
	if !res.ValidHost {
		t.Error("ValidHost = false, want true")
	}
	if !res.Start.Equal(cert.NotBefore) || !res.End.Equal(cert.NotAfter) {
		t.Errorf("Start/End = %v/%v, want %v/%v", res.Start, res.End, cert.NotBefore, cert.NotAfter)
	}
	if want := serialNumberS(cert); res.SerialNumber != want {
		t.Errorf("SerialNumber = %q, want %q", res.SerialNumber, want)
	}
	if want := sha256Fingerprint(cert); res.SHA256Fingerprint != want {
		t.Errorf("SHA256Fingerprint = %q, want %q", res.SHA256Fingerprint, want)
	}
}

// setDialTimeout shortens dialTimeout for the duration of a test.
func setDialTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := dialTimeout
	dialTimeout = d
	t.Cleanup(func() { dialTimeout = orig })
}

func TestExecDefaultPort(t *testing.T) {
	// An address without a port should default to 443. Only the address
	// matters here; the short timeout keeps a silent listener on the test
	// machine's port 443 from stalling the test.
	setDialTimeout(t, 500*time.Millisecond)
	if res := exec("127.0.0.1"); res.Address != "127.0.0.1:443" {
		t.Errorf("Address = %q, want %q", res.Address, "127.0.0.1:443")
	}
}

func TestExecConnectionError(t *testing.T) {
	srv := newTLSServer(t)
	addr := srv.Listener.Addr().String()
	srv.Close()

	if res := exec(addr); res.Error == nil {
		t.Errorf("exec(%q) on a closed server: expected an error", addr)
	}
}

func TestGetResults(t *testing.T) {
	var addrs []string
	for i := 0; i < 5; i++ {
		addrs = append(addrs, newTLSServer(t).Listener.Addr().String())
	}

	// Results must come back in argument order regardless of which
	// connection finishes first.
	for run := 0; run < 10; run++ {
		results := getResults(addrs...)
		if len(results) != len(addrs) {
			t.Fatalf("getResults() returned %d results, want %d", len(results), len(addrs))
		}

		for i, res := range results {
			if res.Error != nil {
				t.Errorf("%s: unexpected error: %v", res.Address, res.Error)
			}
			if res.Address != addrs[i] {
				t.Fatalf("results[%d].Address = %q, want %q", i, res.Address, addrs[i])
			}
		}
	}
}

func TestExecLegacyServer(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
		cipher  uint16
		want    string
	}{
		{"RSA key exchange", tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "RSA/AES_128_GCM/SHA256"},
		{"3DES", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "ECDHE_RSA/3DES_EDE_CBC/SHA"},
		{"TLS 1.0", tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE_RSA/AES_128_CBC/SHA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS = &tls.Config{
				MinVersion:   tt.version,
				MaxVersion:   tt.version,
				CipherSuites: []uint16{tt.cipher},
			}
			srv.StartTLS()
			t.Cleanup(srv.Close)

			res := exec(srv.Listener.Addr().String())
			if res.Error != nil {
				t.Fatalf("exec() error: %v", res.Error)
			}
			if res.Cipher != tt.want {
				t.Errorf("Cipher = %q, want %q", res.Cipher, tt.want)
			}
			if want := sslVersionS(tt.version); res.Version != want {
				t.Errorf("Version = %q, want %q", res.Version, want)
			}
		})
	}
}

func TestExecHandshakeTimeout(t *testing.T) {
	// A server that accepts TCP connections but never speaks TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		<-done
		conn.Close()
	}()

	setDialTimeout(t, 200*time.Millisecond)
	resc := make(chan *Result, 1)
	go func() { resc <- exec(ln.Addr().String()) }()

	// Fail cleanly rather than hanging the whole test run if the timeout
	// stops being applied.
	select {
	case res := <-resc:
		if res.Error == nil {
			t.Fatal("exec() against a silent server: expected a timeout error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec() did not return; dialTimeout is not being applied")
	}
}
