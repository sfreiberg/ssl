package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
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
		0:                                           "Unknown",
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
	if got, want := hexEncode([]byte{0x01, 0xab, 0xff}), "01 AB FF"; got != want {
		t.Errorf("hexEncode() = %q, want %q", got, want)
	}
}

func TestSerialNumberS(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(0x0a0b0c)}
	if got, want := serialNumberS(cert), "0A 0B 0C"; got != want {
		t.Errorf("serialNumberS() = %q, want %q", got, want)
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

func TestSplitAddr(t *testing.T) {
	tests := []struct {
		addr, host, hostport string
	}{
		{"example.com", "example.com", "example.com:443"},
		{"example.com:8443", "example.com", "example.com:8443"},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1:443"},
		{"127.0.0.1:993", "127.0.0.1", "127.0.0.1:993"},
		{"[::1]", "::1", "[::1]:443"},
		{"::1", "::1", "[::1]:443"},
		{"[::1]:8443", "::1", "[::1]:8443"},
		{"[2001:db8::1]", "2001:db8::1", "[2001:db8::1]:443"},
		{"[fe80::1%en0]", "fe80::1%en0", "[fe80::1%en0]:443"},
		{"fe80::1%en0", "fe80::1%en0", "[fe80::1%en0]:443"},
		// Unbalanced brackets are left alone so the dial fails rather than
		// silently "fixing" a typo.
		{"[::1", "[::1", "[[::1]:443"},
		{"::1]", "::1]", "[::1]]:443"},
	}

	for _, tt := range tests {
		host, hostport := splitAddr(tt.addr)
		if host != tt.host || hostport != tt.hostport {
			t.Errorf("splitAddr(%q) = %q, %q, want %q, %q", tt.addr, host, hostport, tt.host, tt.hostport)
		}
	}
}

func TestExecDefaultPort(t *testing.T) {
	// An address without a port should default to 443. Loopback either
	// connects or is refused immediately; only the address matters here.
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
	a, b := newTLSServer(t), newTLSServer(t)
	addrs := []string{a.Listener.Addr().String(), b.Listener.Addr().String()}

	results := getResults(addrs...)
	if len(results) != len(addrs) {
		t.Fatalf("getResults() returned %d results, want %d", len(results), len(addrs))
	}

	seen := map[string]bool{}
	for _, res := range results {
		if res.Error != nil {
			t.Errorf("%s: unexpected error: %v", res.Address, res.Error)
		}
		seen[res.Address] = true
	}
	for _, addr := range addrs {
		if !seen[addr] {
			t.Errorf("missing result for %s", addr)
		}
	}
}
