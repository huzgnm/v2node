package control

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Where the agent's logs end up besides its own files: systemd keeps them in
// the journal and, on Debian/Ubuntu/CentOS, rsyslog copies them again into
// /var/log/syslog or /var/log/messages, which then rotate into .1, .2.gz...
// A node that logs a lot fills the disk through those copies.
//
// Swapped out in tests.
var (
	varLogDir       = "/var/log"
	journaldDropIn  = "/etc/systemd/journald.conf.d/99-mosvpn-v2node.conf"
	rsyslogDir      = "/etc/rsyslog.d"
	rsyslogDropIn   = "/etc/rsyslog.d/30-mosvpn-v2node.conf"
	cleanPackages   = defaultCleanPackages
	restartService  = func(name string) { run(10*time.Second, "systemctl", "restart", name) }
	biggestDirsFunc = biggestDirs
)

const (
	journaldLimit = "[Journal]\nSystemMaxUse=200M\nRuntimeMaxUse=50M\n"
	// The unit runs /usr/local/v2node/v2node, so its syslog tag is "v2node".
	rsyslogStop = "# MosVPN: v2node already logs to the journal; do not copy it again.\nif $programname == 'v2node' then stop\n"
	// Live syslog files above this are emptied when the disk is nearly full.
	bigSyslog = 50 * mb
)

// Files logrotate already rotated away: syslog.1, messages-20261101,
// kern.log.2.gz... Nothing writes to them any more.
var rotatedLog = regexp.MustCompile(`(\.\d+|-\d{8}|\.old)(\.(gz|xz|bz2|zst))?$|\.(gz|xz|bz2|zst)$`)

// Live files rsyslog writes the agent's copy into.
var syslogFiles = []string{"syslog", "messages", "daemon.log", "user.log"}

// LimitNodeLogs caps the journal and stops rsyslog from duplicating the
// agent's logs, so a busy node cannot fill the disk through them. It only
// writes its own drop-in files and does nothing if they are already in place.
func LimitNodeLogs() {
	if runtime.GOOS != "linux" {
		return
	}
	limitNodeLogs()
}

func limitNodeLogs() {
	if writeIfChanged(journaldDropIn, journaldLimit) {
		restartService("systemd-journald")
		log.Info("control: journal capped at 200 MB")
	}
	if info, err := os.Stat(rsyslogDir); err == nil && info.IsDir() {
		if writeIfChanged(rsyslogDropIn, rsyslogStop) {
			restartService("rsyslog")
			log.Info("control: rsyslog no longer copies v2node logs")
		}
	}
}

func writeIfChanged(path, content string) bool {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false
	}
	if err := writeAtomic(path, []byte(content)); err != nil {
		log.WithField("path", path).Warn("control: could not write " + err.Error())
		return false
	}
	return true
}

// freeSystemLogs is the last resort when the disk is nearly full: old
// rotated logs, oversized live syslog files (mostly the agent's own copy) and
// the package manager's download cache. These are what fills a node's disk
// in practice; nothing else on the machine is touched.
func freeSystemLogs(dir string, c *cleanup) {
	var rotated uint64
	_ = filepath.Walk(varLogDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() || !rotatedLog.MatchString(info.Name()) {
			return nil
		}
		if os.Remove(p) == nil {
			rotated += uint64(info.Size())
		}
		return nil
	})
	c.add("old system logs", rotated)

	var live uint64
	for _, name := range syslogFiles {
		p := filepath.Join(varLogDir, name)
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() < bigSyslog {
			continue
		}
		if os.Truncate(p, 0) == nil {
			live += uint64(info.Size())
		}
	}
	c.add("syslog", live)

	before, _ := freeBytes(dir)
	cleanPackages()
	if after, err := freeBytes(dir); err == nil && after > before {
		c.add("package cache", after-before)
	}
}

func defaultCleanPackages() {
	switch {
	case lookPath("apt-get"):
		run(2*time.Minute, "apt-get", "clean")
	case lookPath("dnf"):
		run(2*time.Minute, "dnf", "clean", "all")
	case lookPath("yum"):
		run(2*time.Minute, "yum", "clean", "all")
	case lookPath("apk"):
		run(2*time.Minute, "apk", "cache", "clean")
	}
}

// biggestDirs names what fills the disk holding dir, two levels down from
// its mount point's root, so the panel can say "/var/log 7120 MB" when there
// is nothing of v2node's left to clean. Bounded in time: on a large disk a
// partial answer beats a stuck beat.
func biggestDirs(dir string, n int) string {
	if runtime.GOOS != "linux" || !lookPath("du") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// -x stays on dir's filesystem; "/" is where every node keeps its data.
	out, _ := exec.CommandContext(ctx, "du", "-x", "-m", "-d", "2", "/").Output()
	type entry struct {
		path string
		mb   int
	}
	var entries []entry
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 2)
		if len(fields) != 2 {
			continue
		}
		size, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		path := fields[1]
		if err != nil || strings.Count(path, "/") != 2 {
			continue
		}
		entries = append(entries, entry{path, size})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mb > entries[j].mb })
	var parts []string
	for i := 0; i < len(entries) && i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s %d MB", entries[i].path, entries[i].mb))
	}
	if len(parts) == 0 {
		return ""
	}
	return "biggest: " + strings.Join(parts, ", ")
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func run(timeout time.Duration, name string, args ...string) {
	path, err := exec.LookPath(name)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = exec.CommandContext(ctx, path, args...).Run()
}
