package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateSystem points every system path the cleanup touches at a scratch
// directory, so no test can reach the real /var/log, /etc or package cache.
func isolateSystem(t *testing.T, logDir string) {
	t.Helper()
	etc := filepath.Join(filepath.Dir(logDir), "etc")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldLog, oldJ, oldRDir, oldR, oldPkg, oldRestart, oldBig := varLogDir, journaldDropIn, rsyslogDir, rsyslogDropIn, cleanPackages, restartService, biggestDirsFunc
	t.Cleanup(func() {
		varLogDir, journaldDropIn, rsyslogDir, rsyslogDropIn, cleanPackages, restartService, biggestDirsFunc = oldLog, oldJ, oldRDir, oldR, oldPkg, oldRestart, oldBig
	})
	varLogDir = logDir
	journaldDropIn = filepath.Join(etc, "systemd", "journald.conf.d", "99-mosvpn-v2node.conf")
	rsyslogDir = filepath.Join(etc, "rsyslog.d")
	rsyslogDropIn = filepath.Join(rsyslogDir, "30-mosvpn-v2node.conf")
	cleanPackages = func() {}
	restartService = func(string) {}
	biggestDirsFunc = func(string, int) string { return "biggest: /var/log 7120 MB" }
}

func TestFreeSystemLogsRemovesRotatedAndEmptiesBigSyslog(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "var-log")
	isolateSystem(t, logDir)
	oldFree := freeBytes
	freeBytes = func(string) (uint64, error) { return 0, nil }
	t.Cleanup(func() { freeBytes = oldFree })

	rotated := []string{"syslog.1", "syslog.2.gz", "messages-20261101", "nginx/access.log.3.gz", "kern.log.old"}
	for _, name := range rotated {
		writeSized(t, filepath.Join(logDir, name), 2*mb)
	}
	writeSized(t, filepath.Join(logDir, "syslog"), 120*mb)  // big live syslog: emptied
	writeSized(t, filepath.Join(logDir, "messages"), 10*mb) // small live file: kept
	writeSized(t, filepath.Join(logDir, "auth.log"), 80*mb) // not a syslog copy: kept

	var c cleanup
	freeSystemLogs("/", &c)
	if got := c.String(); got != "cleaned 130 MB: old system logs 10 MB, syslog 120 MB" {
		t.Fatalf("got %q", got)
	}
	for _, name := range rotated {
		if _, err := os.Stat(filepath.Join(logDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", name)
		}
	}
	size := func(name string) int64 {
		info, err := os.Stat(filepath.Join(logDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return info.Size()
	}
	if size("syslog") != 0 || size("messages") != 10*mb || size("auth.log") != 80*mb {
		t.Fatalf("syslog=%d messages=%d auth.log=%d", size("syslog"), size("messages"), size("auth.log"))
	}
}

func TestLimitNodeLogsWritesDropInsOnce(t *testing.T) {
	isolateSystem(t, filepath.Join(t.TempDir(), "var-log"))
	if err := os.MkdirAll(rsyslogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var restarted []string
	restartService = func(name string) { restarted = append(restarted, name) }

	limitNodeLogs()
	j, _ := os.ReadFile(journaldDropIn)
	r, _ := os.ReadFile(rsyslogDropIn)
	if !strings.Contains(string(j), "SystemMaxUse=200M") || !strings.Contains(string(r), "$programname == 'v2node' then stop") {
		t.Fatalf("journald=%q rsyslog=%q", j, r)
	}
	if strings.Join(restarted, ",") != "systemd-journald,rsyslog" {
		t.Fatalf("restarted %v", restarted)
	}

	// Already in place: no rewrite, no restart.
	restarted = nil
	limitNodeLogs()
	if len(restarted) != 0 {
		t.Fatalf("restarted again: %v", restarted)
	}
}

func TestLimitNodeLogsSkipsRsyslogWhenAbsent(t *testing.T) {
	isolateSystem(t, filepath.Join(t.TempDir(), "var-log"))
	limitNodeLogs()
	if _, err := os.Stat(rsyslogDropIn); !os.IsNotExist(err) {
		t.Fatal("rsyslog drop-in written on a machine without rsyslog")
	}
}

func TestDiskFullDetailNamesWhatFillsTheDisk(t *testing.T) {
	e := &errDiskFull{dir: "/usr/local/v2node", free: 0, need: 176 * mb, cleaned: 340 * mb, biggest: "biggest: /var/log 7120 MB, /root 1043 MB"}
	want := "disk full: 0 MB free on /usr/local/v2node, need ~176 MB (cleaned 340 MB); biggest: /var/log 7120 MB, /root 1043 MB; free space then retry"
	if got := e.Error(); got != want {
		t.Fatalf("got %q", got)
	}
	if len(want) > 200 {
		t.Fatalf("detail is %d chars, the panel shows 200", len(want))
	}
}
