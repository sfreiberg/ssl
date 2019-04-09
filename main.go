package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Result holds the results of the TLS end point
type Result struct {
	Address           string    `json:"address"`
	Start             time.Time `json:"start"`
	End               time.Time `json:"end"`
	ValidHost         bool      `json:"validHostname" yaml:"validHostname"`
	Expired           bool      `json:"expired"`
	Version           string    `json:"version"`
	Cipher            string    `json:"cipher"`
	SerialNumber      string    `json:"serialNumber" yaml:"serialNumber"`
	SHA256Fingerprint string    `json:"sha256Fingerprint" yaml:"sha256Fingerprint"`
	Error             error     `json:"error"`
}

// Results hold an array of Result structs. This is used for group activities like exporting to json.
type Results []*Result

func (r Results) String() {
	for _, res := range r {
		fmt.Printf("%s\n", res.Address)
		if res.Expired {
			color.Red("  Expired:\t\t%v\n", res.Expired)
		} else {
			color.Green("  Expired:\t\t%v\n", res.Expired)
		}

		fmt.Printf("  Start:\t\t%v\n", res.Start)
		fmt.Printf("  End:\t\t\t%v\n", res.End)
		fmt.Printf("  Valid Host:\t\t%v\n", res.ValidHost)
		fmt.Printf("  Version:\t\t%v\n", res.Version)
		fmt.Printf("  Cipher Suite:\t\t%v\n", res.Cipher)
		fmt.Printf("  Serial Number:\t%s\n", res.SerialNumber)
		fmt.Printf("  SHA256 Fingerprint:\t%s\n", res.SHA256Fingerprint)
	}

}

func init() {
	// Enable TLS 1.3. Disabled by default in go 1.12
	// See: https://golang.org/pkg/crypto/tls/
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
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

func getResults(addresses ...string) Results {
	results := Results{}
	mtx := &sync.Mutex{}
	wg := &sync.WaitGroup{}

	for _, addr := range addresses {
		wg.Add(1)

		go func(address string) {
			result := exec(address)
			mtx.Lock()
			results = append(results, result)
			mtx.Unlock()
			wg.Done()
		}(addr)
	}

	wg.Wait()

	return results
}

func exec(addr string) *Result {
	config := &tls.Config{InsecureSkipVerify: true}
	result := &Result{}

	host, port, err := net.SplitHostPort(addr)
	// If there's an error we're going to assume it's because
	// there's no port and we'll add a port.
	if err != nil {
		host = addr
		port = "443"
		addr = net.JoinHostPort(host, port)
	}
	result.Address = addr

	conn, err := tls.Dial("tcp", addr, config)
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

// Returns the serial number of the last cert as a string
func serialNumberS(cert *x509.Certificate) string {
	serial := cert.SerialNumber
	b := serial.Bytes()
	return hexEncode(b)
}

func sha256Fingerprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)
	return hexEncode(h.Sum(nil))
}

func hexEncode(b []byte) string {
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
		return "ECDHE_RSA/AES_128_GCM/SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_ECDSA/AES_128_GCM/SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA/AES_256_GCM/SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_ECDSA/AES_256_GCM/SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_RSA/CHACHA20/POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "ECDHE_ECDSA/CHACHA20/POLY1305"
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
