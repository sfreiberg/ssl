// Accept SHA-1 signatures in TLS 1.2 handshakes (disabled by default since
// Go 1.25) so servers that only support them can still be inspected.
//go:debug tlssha1=1

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// dialTimeout bounds the TCP connect and TLS handshake for each address.
var dialTimeout = 10 * time.Second

// Result holds what was learned about a single TLS endpoint.
type Result struct {
	Address           string    `json:"address"`
	Start             time.Time `json:"start"`
	End               time.Time `json:"end"`
	ValidHost         bool      `json:"validHostname"`
	Expired           bool      `json:"expired"`
	Version           string    `json:"version"`
	Cipher            string    `json:"cipher"`
	SerialNumber      string    `json:"serialNumber"`
	SHA256Fingerprint string    `json:"sha256Fingerprint"`
	Error             error     `json:"error"`
}

// Results holds the Result for each address that was checked.
type Results []*Result

func (r Results) String() {
	r.Fprint(color.Output)
}

// Fprint writes a human readable report for each result to w. Addresses that
// could not be checked show the error instead of the certificate details.
func (r Results) Fprint(w io.Writer) {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)

	for _, res := range r {
		fmt.Fprintf(w, "%s\n", res.Address)
		if res.Error != nil {
			red.Fprintf(w, "  Error:\t\t%v\n", res.Error)
			continue
		}

		if res.Expired {
			red.Fprintf(w, "  Expired:\t\t%v\n", res.Expired)
		} else {
			green.Fprintf(w, "  Expired:\t\t%v\n", res.Expired)
		}

		fmt.Fprintf(w, "  Start:\t\t%v\n", res.Start)
		fmt.Fprintf(w, "  End:\t\t\t%v\n", res.End)
		fmt.Fprintf(w, "  Valid Host:\t\t%v\n", res.ValidHost)
		fmt.Fprintf(w, "  Version:\t\t%v\n", res.Version)
		fmt.Fprintf(w, "  Cipher Suite:\t\t%v\n", res.Cipher)
		fmt.Fprintf(w, "  Serial Number:\t%s\n", res.SerialNumber)
		fmt.Fprintf(w, "  SHA256 Fingerprint:\t%s\n", res.SHA256Fingerprint)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: ssl <address[:port]> ...\n")
		fmt.Printf("example: ssl gmail.com imap.gmail.com:993\n")

		os.Exit(1)
	}

	results := getResults(os.Args[1:]...)
	results.String()
}

// getResults checks each address concurrently and returns the results in
// the same order as addresses.
func getResults(addresses ...string) Results {
	results := make(Results, len(addresses))
	wg := &sync.WaitGroup{}

	for i, addr := range addresses {
		wg.Add(1)

		go func(i int, address string) {
			defer wg.Done()
			// Each goroutine writes only its own index, so no lock is needed.
			results[i] = exec(address)
		}(i, addr)
	}

	wg.Wait()

	return results
}

// allCipherSuites returns every cipher suite Go implements, including the
// insecure ones, so legacy servers can still be inspected. The TLS 1.3 suites
// in the list are ignored by crypto/tls; they are not configurable and are
// always enabled.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

func exec(addr string) *Result {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites(),
	}
	result := &Result{}

	host, addr := splitAddr(addr)
	result.Address = addr

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", addr, config)
	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	result.Version = sslVersionS(state.Version)
	result.Cipher = cipherS(state.CipherSuite)
	result.Start = certStart(state.PeerCertificates)
	result.End = certEnd(state.PeerCertificates)
	result.ValidHost = validHostname(host, state.PeerCertificates)
	result.Expired = expired(result.Start, result.End)
	result.SerialNumber = serialNumberS(state.PeerCertificates[0])
	result.SHA256Fingerprint = sha256Fingerprint(state.PeerCertificates[0])

	return result
}

// splitAddr returns the host to verify the certificate against and the
// host:port to dial. If addr has no port, 443 is used. IPv6 literals may be
// given with or without brackets, e.g. [::1], ::1 or [::1]:8443.
func splitAddr(addr string) (host, hostport string) {
	host, port, err := net.SplitHostPort(addr)
	// If there's an error we're going to assume it's because
	// there's no port and we'll add a port.
	if err != nil {
		host = addr
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		port = "443"
	}

	return host, net.JoinHostPort(host, port)
}

// serialNumberS returns the certificate's serial number as hex bytes.
func serialNumberS(cert *x509.Certificate) string {
	serial := cert.SerialNumber
	b := serial.Bytes()
	if len(b) == 0 {
		// A zero serial has no bytes; show it as a single zero byte.
		b = []byte{0}
	}
	return hexEncode(b)
}

func sha256Fingerprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)
	return hexEncode(h.Sum(nil))
}

func hexEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ' ')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}

func validHostname(host string, certs []*x509.Certificate) bool {
	for _, cert := range certs {
		err := cert.VerifyHostname(host)
		if err == nil {
			return true
		}
	}

	return false
}

func sslVersionS(ver uint16) string {
	switch ver {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}

	return "Unknown"
}

func cipherS(cipher uint16) string {
	switch cipher {
	// TLS 1.0 - 1.2 cipher suites
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "RSA/RC4_128/SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "RSA/3DES_EDE_CBC/SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "RSA/AES_128_CBC/SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "RSA/AES_256_CBC/SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "RSA/AES_128_CBC/SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "RSA/AES_128_GCM/SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "RSA/AES_256_GCM/SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "ECDHE_ECDSA/RC4_128/SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "ECDHE_ECDSA/AES_128_CBC/SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "ECDHE_ECDSA/AES_256_CBC/SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "ECDHE_RSA/RC4_128/SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "ECDHE_RSA/3DES_EDE_CBC/SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "ECDHE_RSA/AES_128_CBC/SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "ECDHE_RSA/AES_256_CBC/SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "ECDHE_ECDSA/AES_128_CBC/SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "ECDHE_RSA/AES_128_CBC/SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_RSA/AES_128_GCM/SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_ECDSA/AES_128_GCM/SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA/AES_256_GCM/SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_ECDSA/AES_256_GCM/SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_RSA/CHACHA20/POLY1305/SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_ECDSA/CHACHA20/POLY1305/SHA256"
	// TLS 1.3 cipher suites
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES_128_GCM/SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES_256_GCM/SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "CHACHA20/POLY1305/SHA256"
	}

	return "Unknown"
}

func expired(start, end time.Time) bool {
	now := time.Now()

	if start.After(now) {
		return true
	}

	if end.Before(now) {
		return true
	}

	return false
}

func certStart(certs []*x509.Certificate) time.Time {
	if len(certs) == 0 {
		return time.Time{}
	} else if len(certs) == 1 {
		return certs[0].NotBefore
	}

	t := certs[0].NotBefore

	for i := range certs {
		if certs[i].NotBefore.After(t) {
			t = certs[i].NotBefore
		}
	}

	return t
}

func certEnd(certs []*x509.Certificate) time.Time {
	if len(certs) == 0 {
		return time.Time{}
	} else if len(certs) == 1 {
		return certs[0].NotAfter
	}

	t := certs[0].NotAfter

	for i := range certs {
		if certs[i].NotAfter.Before(t) {
			t = certs[i].NotAfter
		}
	}

	return t
}
