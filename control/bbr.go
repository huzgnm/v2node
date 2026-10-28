package control

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Kernel knobs BBR needs. Variables rather than constants so tests can point
// them at a scratch directory instead of the real /proc and /etc.
var (
	procCongestion = "/proc/sys/net/ipv4/tcp_congestion_control"
	procAvailable  = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	procQdisc      = "/proc/sys/net/core/default_qdisc"
	// Same file install.sh writes, so the two paths never leave the machine
	// with two disagreeing settings.
	bbrSysctlFile = "/etc/sysctl.d/99-mosvpn-bbr.conf"
	loadBBRModule = func() {
		if path, err := exec.LookPath("modprobe"); err == nil {
			_ = exec.Command(path, "tcp_bbr").Run()
		}
	}
)

const bbrSysctl = "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"

// enableBBR switches the host to BBR now and keeps it across reboots. It only
// affects TCP (vless/vmess/trojan/shadowsocks); hysteria2 and tuic pick their
// own congestion control. Connections already open keep their algorithm, new
// ones use BBR, so nothing has to restart.
func enableBBR() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("bbr is only supported on linux")
	}
	return applyBBR()
}

func applyBBR() (string, error) {
	before := readKnob(procCongestion)
	if !bbrAvailable() {
		loadBBRModule()
		if !bbrAvailable() {
			return "", fmt.Errorf("kernel has no bbr (available: %s)", readKnob(procAvailable))
		}
	}

	// Persist first: if the live switch then fails (a container with a
	// read-only /proc), the next boot of a real host still comes up with BBR.
	if err := writeAtomic(bbrSysctlFile, []byte(bbrSysctl)); err != nil {
		return "", fmt.Errorf("write %s: %w", bbrSysctlFile, err)
	}

	// fq is recommended alongside BBR but not required since kernel 4.13, so a
	// failure here is reported rather than fatal.
	qdiscNote := ""
	if err := os.WriteFile(procQdisc, []byte("fq"), 0o644); err != nil {
		qdiscNote = ", qdisc unchanged: " + err.Error()
	}
	if err := os.WriteFile(procCongestion, []byte("bbr"), 0o644); err != nil {
		// Inside a container the saved file does nothing; on a real host it
		// takes effect at the next boot. Say so, or the panel shows a plain
		// failure for a machine that will in fact come up with BBR.
		return "", fmt.Errorf("switch to bbr: %w; saved to %s, applies after reboot", err, bbrSysctlFile)
	}
	if now := readKnob(procCongestion); now != "bbr" {
		return "", fmt.Errorf("kernel still reports %q after switching", now)
	}

	if before == "bbr" {
		return "bbr already on" + qdiscNote, nil
	}
	return fmt.Sprintf("bbr on (was %s)%s", before, qdiscNote), nil
}

func bbrAvailable() bool {
	for _, name := range strings.Fields(readKnob(procAvailable)) {
		if name == "bbr" {
			return true
		}
	}
	return false
}

func readKnob(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(raw))
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
