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
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
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
func Start(nodes []conf.NodeConfig, configPath, version string) *Manager {
	groups := make(map[string]map[int]string)
	tls := make(map[string][2]string)
	for i := range nodes {
		c := nodes[i].Control
		if c == nil || c.Listen == "" || c.Secret == "" {
			continue
		}
		if groups[c.Listen] == nil {
			groups[c.Listen] = make(map[int]string)
		}
		groups[c.Listen][nodes[i].NodeID] = c.Secret
		if c.CertFile != "" && c.KeyFile != "" {
			tls[c.Listen] = [2]string{c.CertFile, c.KeyFile}
		}
	}

	m := &Manager{}
	for listen, secrets := range groups {
		h := &handler{
			secrets:    secrets,
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
		m.servers = append(m.servers, srv)
		pair, secure := tls[listen]
		go func(s *http.Server, addr string, pair [2]string, secure bool) {
			var err error
			if secure {
				log.Infof("control: listening on https://%s", addr)
				err = s.ListenAndServeTLS(pair[0], pair[1])
			} else {
				log.Warnf("control: listening on http://%s without TLS; the panel only accepts https in production", addr)
				err = s.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.WithField("err", err).Error("control: listener stopped")
			}
		}(srv, listen, pair, secure)
	}
	return m
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
