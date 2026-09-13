// Package control exposes the panel -> agent command channel used by the
// MosVPN panel: the panel signs each request with the node's own secret and
// the agent verifies it before acting.
//
// Contract: docs/mosvpn-v2node-control.md in the panel repository.
//
//	POST /v2node/control/{ping,reconfig,update,restart}
//	X-Mosvpn-Timestamp: <unix seconds>
//	X-Mosvpn-Node:      <node id>
//	X-Mosvpn-Signature: hex(HMAC_SHA256(secret, ts \n POST \n path \n hex(sha256(body))))
//
// A request is accepted only when the signature matches the secret of the node
// named in the header and the timestamp is within maxSkew, so a captured
// request cannot be replayed.
package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

const (
	maxSkew     = 30 * time.Second
	maxBodySize = 1 << 20
)

type Manager struct {
	servers []*http.Server
}

type handler struct {
	secrets    map[int]string
	configPath string
	version    string
	startedAt  time.Time
}

// Start launches one listener per distinct Control.Listen found in the node
// configs. Nodes without a Control block are simply not reachable, which keeps
// the channel opt-in.
//
// The channel is https by default and needs no certificate configuration: the
// listener reuses the certificate the node already holds (see cert.go).
func Start(nodes []conf.NodeConfig, configPath, version string) *Manager {
	type group struct {
		secrets     map[int]string
		explicit    []certPair
		ids         []int
		secureIDs   []int
		insecureIDs []int
	}
	groups := make(map[string]*group)
	for i := range nodes {
		c := nodes[i].Control
		if c == nil || c.Listen == "" || c.Secret == "" {
			continue
		}
		g := groups[c.Listen]
		if g == nil {
			g = &group{secrets: make(map[int]string)}
			groups[c.Listen] = g
		}
		g.secrets[nodes[i].NodeID] = c.Secret
		g.ids = append(g.ids, nodes[i].NodeID)
		if c.CertFile != "" && c.KeyFile != "" {
			g.explicit = append(g.explicit, certPair{certFile: c.CertFile, keyFile: c.KeyFile})
		}
		if c.Insecure {
			g.insecureIDs = append(g.insecureIDs, nodes[i].NodeID)
		} else {
			g.secureIDs = append(g.secureIDs, nodes[i].NodeID)
		}
	}

	m := &Manager{}
	for listen, g := range groups {
		h := &handler{
			secrets:    g.secrets,
			configPath: configPath,
			version:    version,
			startedAt:  time.Now(),
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/v2node/control/", h.serve)
		srv := &http.Server{
			Addr:              listen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		insecure := plaintextAllowed(listen, g.secureIDs, g.insecureIDs)
		if !insecure {
			resolver := newCertResolver(g.explicit, g.ids, certDirs(configPath))
			srv.TLSConfig = &tls.Config{
				MinVersion:     tls.VersionTLS12,
				GetCertificate: resolver.GetCertificate,
			}
		}
		m.servers = append(m.servers, srv)

		go func(s *http.Server, addr string, insecure bool) {
			var err error
			if insecure {
				log.Warnf("control: listening on http://%s without TLS; the panel only accepts https in production", addr)
				err = s.ListenAndServe()
			} else {
				log.Infof("control: listening on https://%s", addr)
				// Empty file names: the certificate comes from TLSConfig.
				err = s.ListenAndServeTLS("", "")
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.WithField("err", err).Error("control: listener stopped")
			}
		}(srv, listen, insecure)
	}
	return m
}

// plaintextAllowed decides whether one listener may serve plain http.
//
// Insecure is a bench switch, but a listener is shared by every node that names
// the same Listen address: on a machine running eight nodes, honouring one node's
// Insecure would put the ApiKey and all eight secrets on the wire in the clear
// and break the seven nodes the panel calls over https. So it takes effect only
// when every node on the listener asks for it AND the listener is bound to
// loopback, which is what a bench looks like. Anything else stays on TLS and says
// why, because quietly downgrading is the failure nobody notices.
func plaintextAllowed(listen string, secureIDs, insecureIDs []int) bool {
	if len(insecureIDs) == 0 {
		return false
	}
	if len(secureIDs) > 0 {
		log.Errorf(
			"control: ignoring Insecure on %s: node(s) %s asked for plain http but node(s) %s did not; serving TLS",
			listen, joinInts(insecureIDs), joinInts(secureIDs),
		)
		return false
	}
	if !isLoopbackListen(listen) {
		log.Errorf(
			"control: ignoring Insecure on %s: plain http is only allowed on a loopback address; serving TLS",
			listen,
		)
		return false
	}

	return true
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

func (m *Manager) Close() {
	for _, s := range m.servers {
		_ = s.Close()
	}
	m.servers = nil
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "error", "error": "method_not_allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "error": "bad_body"})
		return
	}

	nodeID, secret, err := h.authenticate(r, body)
	if err != nil {
		log.WithField("err", err).Warn("control: rejected request")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	_ = secret

	switch r.URL.Path {
	case "/v2node/control/ping":
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": h.version,
			"node_id": nodeID,
			"uptime":  int(time.Since(h.startedAt).Seconds()),
		})
	case "/v2node/control/reconfig":
		h.reconfig(w, nodeID, body)
	case "/v2node/control/update":
		h.update(w, body)
	case "/v2node/control/restart":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		scheduleRestart()
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "error": "unknown_command"})
	}
}

// authenticate returns the node id the request claims once its signature and
// freshness check out.
func (h *handler) authenticate(r *http.Request, body []byte) (int, string, error) {
	nodeID, err := strconv.Atoi(r.Header.Get("X-Mosvpn-Node"))
	if err != nil {
		return 0, "", errors.New("bad_node_header")
	}
	secret, ok := h.secrets[nodeID]
	if !ok {
		return 0, "", errors.New("unknown_node")
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Mosvpn-Timestamp"), 10, 64)
	if err != nil {
		return 0, "", errors.New("bad_timestamp")
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > maxSkew {
		return 0, "", errors.New("stale_timestamp")
	}

	sum := sha256.Sum256(body)
	stringToSign := strconv.FormatInt(ts, 10) + "\nPOST\n" + r.URL.Path + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	expected := mac.Sum(nil)

	got, err := hex.DecodeString(r.Header.Get("X-Mosvpn-Signature"))
	if err != nil || !hmac.Equal(expected, got) {
		return 0, "", errors.New("bad_signature")
	}
	return nodeID, secret, nil
}

type reconfigRequest struct {
	ApiHost string `json:"api_host"`
	ApiKey  string `json:"api_key"`
}

func (h *handler) reconfig(w http.ResponseWriter, nodeID int, body []byte) {
	var req reconfigRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "error": "bad_json"})
			return
		}
	}
	if req.ApiHost == "" && req.ApiKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "error": "nothing_to_apply"})
		return
	}

	applied, err := rewriteNodeConfig(h.configPath, nodeID, req.ApiHost, req.ApiKey)
	if err != nil {
		log.WithField("err", err).Error("control: reconfig failed")
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "error": "write_failed"})
		return
	}
	// The file watcher picks the change up and reloads the node; no restart.
	log.Infof("control: reconfig node %d applied %v", nodeID, applied)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "applied": applied})
}

type updateRequest struct {
	Ref string `json:"ref"`
}

func (h *handler) update(w http.ResponseWriter, body []byte) {
	req := updateRequest{Ref: "latest"}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "error": "bad_json"})
			return
		}
	}
	if req.Ref == "" {
		req.Ref = "latest"
	}
	// Defence in depth: the panel already whitelists this, but the ref reaches
	// a root-run installer here, so it is validated again before use.
	if !refPattern.MatchString(req.Ref) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "error": "invalid_ref"})
		return
	}

	tag, err := selfUpdate(req.Ref)
	if err != nil {
		log.WithField("err", err).Error("control: update failed")
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "from": h.version, "to": tag})
	// Answer first, then swap in the new binary by restarting.
	scheduleRestart()
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
