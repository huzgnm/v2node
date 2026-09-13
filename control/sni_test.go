package control

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert puts a self-signed pair for one domain where the resolver looks for
// node nodeID's certificate.
func writeCert(t *testing.T, dir, protocol string, nodeID int, domain string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, protocol+itoa(nodeID))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(base+".cer", certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".key", keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func itoa(v int) string {
	return string([]byte{byte('0' + v/10), byte('0' + v%10)})
}

// One agent serves several nodes from one config — 8 node ids on one machine on
// this fleet — and each node has its own certificate. Answering every handshake
// with the first certificate found would fail verification for all but one node.
func TestServesTheCertificateMatchingTheRequestedName(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "vless", 61, "a61.example.com")
	writeCert(t, dir, "vless", 62, "b62.example.com")
	writeCert(t, dir, "trojan", 63, "c63.example.com")

	r := newCertResolver(nil, []int{61, 62, 63}, []string{dir})

	for _, want := range []string{"a61.example.com", "b62.example.com", "c63.example.com"} {
		cert, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: want})
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		leaf := leafOf(cert)
		if leaf == nil {
			t.Fatalf("%s: no leaf", want)
		}
		if err := leaf.VerifyHostname(want); err != nil {
			t.Fatalf("served the wrong certificate for %s: got %v", want, leaf.DNSNames)
		}
	}

	// An unknown name still gets an answer: a handshake failure would surface to
	// the panel as a bare "unreachable" instead of a name mismatch it can report.
	if _, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "nobody.example.com"}); err != nil {
		t.Fatalf("unknown name must still be answered: %v", err)
	}

	// A client that sends no SNI at all (an IP in the URL) also gets one.
	if _, err := r.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("no SNI must still be answered: %v", err)
	}
}

func TestRenewedCertificateIsPickedUpWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "vless", 61, "a61.example.com")
	r := newCertResolver(nil, []int{61}, []string{dir})

	first, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "a61.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// Renewal rewrites the file in place under a new name; mtime moves with it.
	time.Sleep(10 * time.Millisecond)
	writeCert(t, dir, "vless", 61, "renewed61.example.com")
	second, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "renewed61.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if leafOf(second).VerifyHostname("renewed61.example.com") != nil {
		t.Fatal("the renewed certificate was not picked up")
	}
	if first == second {
		t.Fatal("the cached certificate must be replaced, not reused")
	}
}
