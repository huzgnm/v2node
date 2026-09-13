package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// The agent already owns a certificate for every node whose panel TLS settings
// ask for one: node/cert.go issues or writes it, and api/v2board/node.go names
// it /etc/v2node/<protocol><NodeID>.cer with the matching .key beside it. The
// control listener reuses that file, so the operator configures nothing: the
// same certificate that serves the node's proxy serves the control channel.
//
// The names are rebuilt from this list rather than pattern-matched, because a
// protocol name may itself end in a digit ("hysteria2"): hysteria2125.cer would
// be indistinguishable from node 2125's certificate under any regexp.
var certProtocols = []string{"vmess", "vless", "trojan", "hysteria2", "tuic", "anytls", "shadowsocks"}

type certPair struct {
	certFile string
	keyFile  string
}

// certResolver answers the TLS handshake with whatever certificate the node
// holds right now.
//
// The lookup is deliberately lazy rather than done once at startup: when the
// agent boots it has not fetched its node config yet, so the certificate file
// usually does not exist for the first few seconds, and it is replaced again on
// every renewal. Resolving per handshake (cached until the file's mtime moves)
// means the channel comes up on its own once the cert lands and follows
// renewals without a restart.
type certResolver struct {
	explicit []certPair
	nodeIDs  []int
	dirs     []string

	mu     sync.Mutex
	cache  map[certPair]cachedCert
	warned bool
}

type cachedCert struct {
	cert    *tls.Certificate
	modTime time.Time
}

func newCertResolver(explicit []certPair, nodeIDs []int, dirs []string) *certResolver {
	sort.Ints(nodeIDs)
	return &certResolver{explicit: explicit, nodeIDs: nodeIDs, dirs: dirs}
}

func (r *certResolver) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// One agent commonly serves several nodes from one config, and each node has
	// its own certificate, so the listener holds several. Pick the one that
	// matches the name the panel asked for; answering with another node's
	// certificate would fail verification on the panel side for every node but
	// one.
	requested := ""
	if hello != nil {
		requested = hello.ServerName
	}

	var first *tls.Certificate
	for _, pair := range r.candidates() {
		info, err := os.Stat(pair.certFile)
		if err != nil {
			continue
		}
		if _, err := os.Stat(pair.keyFile); err != nil {
			continue
		}
		cert := r.load(pair, info.ModTime())
		if cert == nil {
			continue
		}
		if first == nil {
			first = cert
		}
		if requested == "" {
			break
		}
		if leaf := leafOf(cert); leaf != nil && leaf.VerifyHostname(requested) == nil {
			r.warned = false
			return cert, nil
		}
	}
	if first != nil {
		// No certificate names what was asked for. Answer with one anyway: the
		// panel decides whether to trust it, and a handshake failure here would
		// read as "unreachable" instead of a name mismatch.
		if requested != "" {
			log.Warnf("control: no certificate for %q, offering the first one found", requested)
		}
		r.warned = false
		return first, nil
	}

	if !r.warned {
		r.warned = true
		log.Warnf(
			"control: no certificate yet for node(s) %s; looked for <protocol><NodeID>.cer in %s. "+
				"Give the node a cert in the panel's TLS settings, or set Control.CertFile/KeyFile.",
			joinInts(r.nodeIDs), strings.Join(r.dirs, ", "),
		)
	}
	return nil, errors.New("control: no certificate available")
}

// load returns the parsed pair, reusing the cached copy while the file on disk
// has not moved. A renewal rewrites the file, which changes its mtime, so the
// new certificate is picked up without a restart.
func (r *certResolver) load(pair certPair, modTime time.Time) *tls.Certificate {
	if cached, ok := r.cache[pair]; ok && cached.modTime.Equal(modTime) {
		return cached.cert
	}
	cert, err := tls.LoadX509KeyPair(pair.certFile, pair.keyFile)
	if err != nil {
		log.WithField("err", err).Warnf("control: cannot use %s", pair.certFile)
		return nil
	}
	if r.cache == nil {
		r.cache = make(map[certPair]cachedCert)
	}
	r.cache[pair] = cachedCert{cert: &cert, modTime: modTime}
	log.Infof("control: loaded certificate %s", pair.certFile)

	return &cert
}

// leafOf parses the leaf once and keeps it on the certificate, so matching a
// hostname does not re-parse on every handshake.
func leafOf(cert *tls.Certificate) *x509.Certificate {
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	cert.Leaf = leaf

	return leaf
}

// candidates lists the certificates to try, operator-configured first. Only
// pairs where both files exist are offered, so a half-written renewal is not
// mistaken for a usable certificate.
func (r *certResolver) candidates() []certPair {
	out := make([]certPair, 0, len(r.explicit)+len(r.nodeIDs))
	out = append(out, r.explicit...)

	for _, dir := range r.dirs {
		for _, id := range r.nodeIDs {
			for _, protocol := range certProtocols {
				base := filepath.Join(dir, protocol+strconv.Itoa(id))
				pair := certPair{certFile: base + ".cer", keyFile: base + ".key"}
				if exists(pair.certFile) && exists(pair.keyFile) {
					out = append(out, pair)
				}
			}
		}
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// certDirs is where issued certificates are looked for: the directory holding
// the agent's own config, plus the /etc/v2node default the panel-driven paths
// in api/v2board/node.go fall back to.
func certDirs(configPath string) []string {
	dirs := []string{"/etc/v2node"}
	if configPath != "" {
		if dir := filepath.Dir(configPath); dir != "" && dir != "." && dir != dirs[0] {
			dirs = append([]string{dir}, dirs...)
		}
	}
	return dirs
}

func (p certPair) String() string {
	return fmt.Sprintf("%s + %s", p.certFile, p.keyFile)
}
