package control

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"
	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

const (
	mb = 1 << 20
	// Headroom kept free beyond the update itself, so the machine is not left
	// at zero bytes for the node and the system while the update runs.
	updateMargin = 50 * mb
	// Assumed size of a release zip when the server does not say.
	defaultZipSize = 64 * mb
	// journalctl keeps at most this much after a vacuum.
	journalKeep = "200M"
)

// Swapped out in tests.
var (
	freeBytes = func(path string) (uint64, error) {
		u, err := disk.Usage(path)
		if err != nil {
			return 0, err
		}
		return u.Free, nil
	}
	vacuumJournal = func() {
		if path, err := exec.LookPath("journalctl"); err == nil {
			_ = exec.Command(path, "--vacuum-size="+journalKeep).Run()
		}
	}
	tempRoots = func() []string { return []string{os.TempDir(), "/tmp", "/var/tmp"} }
)

// errDiskFull is what the admin sees in the panel, so it says what is free,
// what is needed and what was already cleaned.
type errDiskFull struct {
	dir     string
	free    uint64
	need    uint64
	cleaned string
}

func (e *errDiskFull) Error() string {
	msg := fmt.Sprintf("disk full: %d MB free on %s, need ~%d MB", e.free/mb, e.dir, e.need/mb)
	if e.cleaned != "" {
		msg += " (" + e.cleaned + ")"
	}
	return msg + "; free space then retry"
}

// cleanup tracks what was removed to make room, for the result detail.
type cleanup struct {
	parts []string
	total uint64
}

func (c *cleanup) add(what string, n uint64) {
	// Below a megabyte it would read "0 MB", which says nothing.
	if n < mb {
		return
	}
	c.parts = append(c.parts, fmt.Sprintf("%s %d MB", what, n/mb))
	c.total += n
}

func (c *cleanup) String() string {
	if c.total == 0 {
		return ""
	}
	return fmt.Sprintf("cleaned %d MB: %s", c.total/mb, strings.Join(c.parts, ", "))
}

// removeLeftovers deletes what earlier updates of this agent left behind and
// nothing else: v2node-update* temp dirs, the .update work dir next to the
// binary and a half-staged <binary>.new.
func removeLeftovers(target string, c *cleanup) {
	var paths []string
	seen := map[string]bool{}
	for _, root := range tempRoots() {
		matches, _ := filepath.Glob(filepath.Join(root, "v2node-update*"))
		paths = append(paths, matches...)
	}
	paths = append(paths, updateWorkDir(target), target+".new")

	var freed uint64
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		size := sizeOf(p)
		if size == 0 {
			if _, err := os.Lstat(p); err != nil {
				continue
			}
		}
		if err := os.RemoveAll(p); err != nil {
			log.WithField("path", p).Warn("control: could not remove update leftover")
			continue
		}
		freed += size
	}
	c.add("old update files", freed)
}

// roomMaker frees space when a write would not fit, at most once per update:
// first this agent's own log files, then the systemd journal.
type roomMaker struct {
	configPath string
	cleaned    cleanup
	tried      bool
}

// ensure checks that dir has need bytes free, freeing logs once if not.
func (r *roomMaker) ensure(dir string, need uint64) error {
	free, err := freeBytes(dir)
	if err != nil {
		// Cannot tell; let the write itself fail with a real error.
		return nil
	}
	if free >= need {
		return nil
	}
	if !r.tried {
		r.tried = true
		freeLogs(r.configPath, dir, &r.cleaned)
		if after, err := freeBytes(dir); err == nil {
			free = after
		}
		if free >= need {
			return nil
		}
	}
	return &errDiskFull{dir: dir, free: free, need: need, cleaned: r.cleaned.String()}
}

// freeLogs empties the log files named in this agent's own config and
// vacuums the journal, which is where the logs go by default. Files are
// truncated, not removed, so the running process keeps writing to them.
func freeLogs(configPath, dir string, c *cleanup) {
	before, _ := freeBytes(dir)
	var own uint64
	for _, p := range ownLogFiles(configPath) {
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		if err := os.Truncate(p, 0); err != nil {
			log.WithField("path", p).Warn("control: could not empty log file")
			continue
		}
		own += uint64(info.Size())
	}
	c.add("v2node logs", own)
	vacuumJournal()
	if after, err := freeBytes(dir); err == nil && after > before+own {
		c.add("journal", after-before-own)
	}
}

// ownLogFiles lists the Log.Output and Log.Access files from the agent's
// config, skipping the special values xray takes instead of a path.
func ownLogFiles(configPath string) []string {
	if configPath == "" {
		return nil
	}
	c := conf.New()
	if err := c.LoadFromPath(configPath); err != nil {
		return nil
	}
	var out []string
	for _, p := range []string{c.LogConfig.Output, c.LogConfig.Access} {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "", "none", "stdout", "stderr":
			continue
		}
		out = append(out, p)
	}
	return out
}

// Disk use above this makes the agent clean up on its own.
const autoCleanUsage = 0.95

// FreeSpaceIfLow cleans up when the disk holding the agent is nearly full:
// leftovers of earlier updates, this agent's log files and the journal. It
// touches nothing else on the machine. Returns what was done, or "".
func FreeSpaceIfLow(configPath string) string {
	target, err := executablePath()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	dir := filepath.Dir(target)
	used, err := usedFraction(dir)
	if err != nil || used < autoCleanUsage {
		return ""
	}
	var c cleanup
	removeLeftovers(target, &c)
	freeLogs(configPath, dir, &c)
	note := fmt.Sprintf("disk %.0f%% full on %s", used*100, dir)
	if done := c.String(); done != "" {
		note += ", " + done
	} else {
		note += ", nothing of v2node's to clean"
	}
	log.Warn("control: " + note)
	return note
}

// Swapped out in tests.
var usedFraction = func(path string) (float64, error) {
	u, err := disk.Usage(path)
	if err != nil || u.Total == 0 {
		return 0, fmt.Errorf("disk usage unavailable")
	}
	return float64(u.Total-u.Free) / float64(u.Total), nil
}

// updateWorkDir is where the download lands: next to the binary, so a small
// or full /tmp does not block the update and only one filesystem has to have
// room.
func updateWorkDir(target string) string {
	return filepath.Join(filepath.Dir(target), ".update")
}

func sizeOf(path string) uint64 {
	var total uint64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
}
