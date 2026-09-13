package control

import (
	"os"
	"path/filepath"
	"testing"
)

// The whole point of the resolver is that the operator configures no cert, so
// these tests pin the discovery rules rather than the TLS plumbing.
func TestDiscoversTheCertTheNodeAlreadyHolds(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("vless125.cer")
	write("vless125.key")

	got := newCertResolver(nil, []int{125}, []string{dir}).candidates()
	if len(got) != 1 || got[0].certFile != filepath.Join(dir, "vless125.cer") {
		t.Fatalf("want vless125.cer, got %v", got)
	}
	if got[0].keyFile != filepath.Join(dir, "vless125.key") {
		t.Fatalf("key must sit beside the cert, got %q", got[0].keyFile)
	}
}

func TestFindsACertOfAProtocolEndingInADigit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"hysteria2125.cer", "hysteria2125.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := newCertResolver(nil, []int{125}, []string{dir}).candidates()
	if len(got) != 1 || got[0].certFile != filepath.Join(dir, "hysteria2125.cer") {
		t.Fatalf("hysteria2 node 125 must resolve, got %v", got)
	}
}

func TestIgnoresCertsOfOtherNodes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"vless2125.cer", "vless2125.key", // node 2125 must not match node 125
		"trojan9.cer", "trojan9.key",
		"vless125.cer", // no .key beside it, so unusable
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := newCertResolver(nil, []int{125}, []string{dir}).candidates(); len(got) != 0 {
		t.Fatalf("want no candidate, got %v", got)
	}
}

func TestExplicitPairWinsOverDiscovery(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vless125.cer", "vless125.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	explicit := certPair{certFile: "/custom/full.cer", keyFile: "/custom/full.key"}

	got := newCertResolver([]certPair{explicit}, []int{125}, []string{dir}).candidates()
	if len(got) != 2 || got[0] != explicit {
		t.Fatalf("operator cert must be tried first, got %v", got)
	}
}

func TestHandshakeFailsCleanlyBeforeTheCertExists(t *testing.T) {
	// The agent starts before it has fetched its node config, so the cert file
	// is missing for the first seconds; that must be an error, never a panic.
	_, err := newCertResolver(nil, []int{125}, []string{t.TempDir()}).GetCertificate(nil)
	if err == nil {
		t.Fatal("want an error while no certificate exists")
	}
}
