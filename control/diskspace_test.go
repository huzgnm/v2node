package control

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateHost fakes the machine an update runs on: a running binary in its own
// directory, a temp root, a release server, and a disk whose free space the
// test controls.
type updateHost struct {
	dir, target, tmp, config string
	free                     func() uint64
	vacuums                  int
}

func newUpdateHost(t *testing.T, release []byte, status int) *updateHost {
	t.Helper()
	// Resolved, as selfUpdate resolves the binary path (macOS /var → /private/var).
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &updateHost{
		dir: filepath.Join(root, "usr-local-v2node"),
		tmp: filepath.Join(root, "tmp"),
	}
	for _, d := range []string{h.dir, h.tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.target = filepath.Join(h.dir, "v2node")
	if err := os.WriteFile(h.target, []byte("OLDBIN"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.config = filepath.Join(root, "config.json")
	if err := os.WriteFile(h.config, []byte(`{"Log":{"Output":"","Access":"none"},"Nodes":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h.free = func() uint64 { return 10 << 30 }

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(release)
	}))
	t.Cleanup(srv.Close)

	oldExe, oldURL, oldFree, oldVac, oldRoots, oldUsed := executablePath, releaseURL, freeBytes, vacuumJournal, tempRoots, usedFraction
	t.Cleanup(func() {
		executablePath, releaseURL, freeBytes, vacuumJournal, tempRoots, usedFraction = oldExe, oldURL, oldFree, oldVac, oldRoots, oldUsed
	})
	executablePath = func() (string, error) { return h.target, nil }
	releaseURL = func(tag, arch string) string { return srv.URL + "/" + tag }
	freeBytes = func(string) (uint64, error) { return h.free(), nil }
	vacuumJournal = func() { h.vacuums++ }
	tempRoots = func() []string { return []string{h.tmp} }
	return h
}

func releaseZip(t *testing.T, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"v2node": binary, "geoip.dat": "geo"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (h *updateHost) binary(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.target)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (h *updateHost) assertNoWorkFiles(t *testing.T) {
	t.Helper()
	for _, p := range []string{updateWorkDir(h.target), h.target + ".new"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", p)
		}
	}
}

func writeSized(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestUpdateInstallsAndCleansUp(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	tag, err := selfUpdate("v9.9.9", h.config)
	if err != nil || tag != "v9.9.9" {
		t.Fatalf("tag = %q, err = %v", tag, err)
	}
	if got := h.binary(t); got != "NEWBIN" {
		t.Fatalf("binary = %q", got)
	}
	h.assertNoWorkFiles(t)
	if h.vacuums != 0 {
		t.Fatal("journal vacuumed although there was room")
	}
}

func TestUpdateRemovesOwnLeftoversOnly(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	writeSized(t, filepath.Join(h.tmp, "v2node-update123", "release.zip"), 5*mb)
	writeSized(t, h.target+".new", 3*mb)
	other := filepath.Join(h.tmp, "someone-else.tmp")
	writeSized(t, other, 1*mb)

	tag, err := selfUpdate("v9.9.9", h.config)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v9.9.9 (cleaned 8 MB: old update files 8 MB)" {
		t.Fatalf("tag = %q", tag)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("removed a file that is not v2node's")
	}
}

func TestUpdateRefusesWhenDiskFull(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	h.free = func() uint64 { return 30 * mb }
	_, err := selfUpdate("v9.9.9", h.config)
	if err == nil {
		t.Fatal("expected disk full")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "disk full: 30 MB free on "+h.dir+", need ~") || !strings.HasSuffix(msg, "; free space then retry") {
		t.Fatalf("message = %q", msg)
	}
	if h.vacuums != 1 {
		t.Fatalf("vacuums = %d, want 1", h.vacuums)
	}
	if got := h.binary(t); got != "OLDBIN" {
		t.Fatalf("running binary touched: %q", got)
	}
	h.assertNoWorkFiles(t)
}

func TestUpdateEmptiesOwnLogsToMakeRoom(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	logFile := filepath.Join(filepath.Dir(h.config), "v2node.log")
	writeSized(t, logFile, 120*mb)
	cfg := `{"Log":{"Output":"` + logFile + `","Access":"none"},"Nodes":[]}`
	if err := os.WriteFile(h.config, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	h.free = func() uint64 {
		if info, err := os.Stat(logFile); err == nil && info.Size() == 0 {
			return 150 * mb
		}
		return 30 * mb
	}
	tag, err := selfUpdate("v9.9.9", h.config)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v9.9.9 (cleaned 120 MB: v2node logs 120 MB)" {
		t.Fatalf("tag = %q", tag)
	}
	if info, err := os.Stat(logFile); err != nil || info.Size() != 0 {
		t.Fatal("log file should be emptied, not removed")
	}
}

func TestUpdateVacuumsJournalToMakeRoom(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	h.free = func() uint64 {
		if h.vacuums > 0 {
			return 300 * mb
		}
		return 30 * mb
	}
	tag, err := selfUpdate("v9.9.9", h.config)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v9.9.9 (cleaned 270 MB: journal 270 MB)" {
		t.Fatalf("tag = %q", tag)
	}
}

func TestUpdateStopsBeforeExtractingWhenDiskFillsUp(t *testing.T) {
	h := newUpdateHost(t, releaseZip(t, "NEWBIN"), http.StatusOK)
	calls := 0
	h.free = func() uint64 {
		calls++
		if calls == 1 {
			return 10 << 30 // room for the download
		}
		return 10 * mb // gone by the time the binary is staged
	}
	_, err := selfUpdate("v9.9.9", h.config)
	if err == nil || !strings.HasPrefix(err.Error(), "disk full: 10 MB free") {
		t.Fatalf("err = %v", err)
	}
	if got := h.binary(t); got != "OLDBIN" {
		t.Fatalf("running binary touched: %q", got)
	}
	h.assertNoWorkFiles(t)
}

func TestFailedDownloadLeavesBinary(t *testing.T) {
	h := newUpdateHost(t, nil, http.StatusNotFound)
	if _, err := selfUpdate("v9.9.9", h.config); err == nil || err.Error() != "download: http 404" {
		t.Fatalf("err = %v", err)
	}
	if got := h.binary(t); got != "OLDBIN" {
		t.Fatalf("running binary touched: %q", got)
	}
}

func TestFreeSpaceIfLow(t *testing.T) {
	h := newUpdateHost(t, nil, http.StatusOK)
	writeSized(t, filepath.Join(h.tmp, "v2node-update9", "release.zip"), 4*mb)

	usedFraction = func(string) (float64, error) { return 0.50, nil }
	if note := FreeSpaceIfLow(h.config); note != "" {
		t.Fatalf("cleaned at 50%%: %q", note)
	}
	if h.vacuums != 0 {
		t.Fatal("journal vacuumed at 50%")
	}

	usedFraction = func(string) (float64, error) { return 0.97, nil }
	note := FreeSpaceIfLow(h.config)
	if note != "disk 97% full on "+h.dir+", cleaned 4 MB: old update files 4 MB" {
		t.Fatalf("note = %q", note)
	}
	if h.vacuums != 1 {
		t.Fatalf("vacuums = %d", h.vacuums)
	}
}

func TestOwnLogFilesSkipsSpecialValues(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfg, []byte(`{"Log":{"Output":"stdout","Access":"/var/log/v2node/access.log"}}`), 0o644)
	got := ownLogFiles(cfg)
	if len(got) != 1 || got[0] != "/var/log/v2node/access.log" {
		t.Fatalf("got %v", got)
	}
	_ = os.WriteFile(cfg, []byte(`{"Log":{"Output":"","Access":"none"}}`), 0o644)
	if got := ownLogFiles(cfg); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

// QA-9: a cleanup of less than a megabyte is not listed as "0 MB".
func TestCleanupSkipsSubMegabyte(t *testing.T) {
	var c cleanup
	c.add("journal", 300<<10)
	c.add("v2node logs", 5*mb)
	if got := c.String(); got != "cleaned 5 MB: v2node logs 5 MB" {
		t.Fatalf("got %q", got)
	}
}
