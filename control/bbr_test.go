package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHost points the BBR knobs at plain files in a temp dir.
func fakeHost(t *testing.T, current, available string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, value string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldCC, oldAvail, oldQdisc, oldFile, oldLoad := procCongestion, procAvailable, procQdisc, bbrSysctlFile, loadBBRModule
	t.Cleanup(func() {
		procCongestion, procAvailable, procQdisc, bbrSysctlFile, loadBBRModule = oldCC, oldAvail, oldQdisc, oldFile, oldLoad
	})
	procCongestion = write("tcp_congestion_control", current)
	procAvailable = write("tcp_available_congestion_control", available)
	procQdisc = write("default_qdisc", "fq_codel")
	bbrSysctlFile = filepath.Join(dir, "sysctl.d", "99-mosvpn-bbr.conf")
	loadBBRModule = func() {}
	return dir
}

func TestApplyBBRSwitchesFromCubic(t *testing.T) {
	fakeHost(t, "cubic", "reno cubic bbr")
	detail, err := applyBBR()
	if err != nil {
		t.Fatal(err)
	}
	if detail != "bbr on (was cubic)" {
		t.Fatalf("detail = %q", detail)
	}
	if got := readKnob(procCongestion); got != "bbr" {
		t.Fatalf("congestion = %q", got)
	}
	if got := readKnob(procQdisc); got != "fq" {
		t.Fatalf("qdisc = %q", got)
	}
	persisted, err := os.ReadFile(bbrSysctlFile)
	if err != nil || string(persisted) != bbrSysctl {
		t.Fatalf("sysctl file = %q, %v", persisted, err)
	}
}

func TestApplyBBRAlreadyOn(t *testing.T) {
	fakeHost(t, "bbr", "reno cubic bbr")
	detail, err := applyBBR()
	if err != nil || detail != "bbr already on" {
		t.Fatalf("detail = %q, err = %v", detail, err)
	}
}

func TestApplyBBRLoadsModule(t *testing.T) {
	fakeHost(t, "cubic", "reno cubic")
	loaded := false
	loadBBRModule = func() {
		loaded = true
		_ = os.WriteFile(procAvailable, []byte("reno cubic bbr\n"), 0o644)
	}
	if _, err := applyBBR(); err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatal("module load not attempted")
	}
}

func TestApplyBBRKernelWithoutBBR(t *testing.T) {
	fakeHost(t, "cubic", "reno cubic")
	_, err := applyBBR()
	if err == nil || !strings.Contains(err.Error(), "kernel has no bbr") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(bbrSysctlFile); !os.IsNotExist(statErr) {
		t.Fatal("sysctl file written although the kernel cannot run bbr")
	}
	if got := readKnob(procCongestion); got != "cubic" {
		t.Fatalf("congestion changed to %q", got)
	}
}

func TestApplyBBRReadOnlyProc(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	dir := fakeHost(t, "cubic", "reno cubic bbr")
	if err := os.Chmod(procCongestion, 0o444); err != nil {
		t.Fatal(err)
	}
	_, err := applyBBR()
	if err == nil || !strings.Contains(err.Error(), "switch to bbr") {
		t.Fatalf("err = %v", err)
	}
	// Still persisted, so a real host comes up with BBR after a reboot.
	if _, statErr := os.Stat(filepath.Join(dir, "sysctl.d", "99-mosvpn-bbr.conf")); statErr != nil {
		t.Fatalf("sysctl file missing: %v", statErr)
	}
}

func TestApplyCommandBBR(t *testing.T) {
	if _, err := os.Stat("/proc/sys"); err == nil {
		t.Skip("would touch the real host")
	}
	res := Apply(Command{ID: "x", Type: "bbr"}, "", 1)
	if res.OK || res.RestartAfter {
		t.Fatalf("non-linux must fail without restart: %+v", res)
	}
}
