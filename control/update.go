package control

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// The release repository this agent updates itself from. It must be the fork
// that carries this control channel: updating from upstream would install a
// binary without it and the node would drop off the panel's control.
const releaseRepo = "huzgnm/v2node"

// Only a plain "latest" or a vX.Y.Z tag may reach the download URL.
var refPattern = regexp.MustCompile(`^(latest|v[0-9]+\.[0-9]+\.[0-9]+)$`)

// rewriteNodeConfig updates ApiHost / ApiKey for one node inside the agent's
// JSON config, preserving every other key, and writes it atomically. The
// running agent's file watcher reloads from the new file.
func rewriteNodeConfig(path string, nodeID int, apiHost, apiKey string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	nodes, ok := doc["Nodes"].([]any)
	if !ok {
		return nil, fmt.Errorf("config has no Nodes array")
	}

	applied := []string{}
	found := false
	for _, entry := range nodes {
		node, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		id, ok := node["NodeID"].(float64)
		if !ok || int(id) != nodeID {
			continue
		}
		found = true
		if apiHost != "" {
			node["ApiHost"] = apiHost
			applied = append(applied, "api_host")
		}
		if apiKey != "" {
			node["ApiKey"] = apiKey
			applied = append(applied, "api_key")
		}
	}
	if !found {
		return nil, fmt.Errorf("node %d not in config", nodeID)
	}

	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	tmp := path + ".mosvpn.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("replace config: %w", err)
	}
	return applied, nil
}

// assetArch mirrors script/install.sh so one naming scheme covers the
// installer, the release workflow and this self-update.
func assetArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "64", nil
	case "arm64":
		return "arm64-v8a", nil
	case "s390x":
		return "s390x", nil
	default:
		return "", fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
}

func resolveTag(ref string) (string, error) {
	if ref != "latest" {
		return ref, nil
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + releaseRepo + "/releases/latest")
	if err != nil {
		return "", fmt.Errorf("resolve latest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve latest: http %d", resp.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("resolve latest: %w", err)
	}
	if payload.TagName == "" {
		return "", fmt.Errorf("resolve latest: no release yet")
	}
	return payload.TagName, nil
}

// Swapped out in tests.
var (
	executablePath = os.Executable
	releaseURL     = func(tag, arch string) string {
		return fmt.Sprintf("https://github.com/%s/releases/download/%s/v2node-linux-%s.zip", releaseRepo, tag, arch)
	}
)

// selfUpdate downloads the release binary for ref and swaps it in. The caller
// restarts the service afterwards so the new binary takes over. Any failure
// leaves the running binary untouched, so the node keeps serving and nothing
// restarts. On success the returned detail mentions what was cleaned to make
// room, if anything.
func selfUpdate(ref, configPath string) (string, error) {
	if !refPattern.MatchString(ref) {
		return "", fmt.Errorf("invalid_ref")
	}
	arch, err := assetArch()
	if err != nil {
		return "", err
	}
	tag, err := resolveTag(ref)
	if err != nil {
		return "", err
	}
	if !refPattern.MatchString(tag) && tag != "latest" {
		// A tag coming back from the API still has to look like a version.
		if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(tag) {
			return "", fmt.Errorf("invalid_tag")
		}
	}

	target, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("locate binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	binDir := filepath.Dir(target)

	// Room first: an earlier update that died half way may be what filled the
	// disk, and none of this needs the network.
	room := &roomMaker{configPath: configPath}
	removeLeftovers(target, &room.cleaned)
	var current uint64
	if info, err := os.Stat(target); err == nil {
		current = uint64(info.Size())
	}
	// The new binary is about the size of the running one; allow it to grow.
	binEstimate := current + current/4

	url := releaseURL(tag, arch)
	log.Infof("control: downloading %s", url)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: http %d", resp.StatusCode)
	}
	zipSize := uint64(defaultZipSize)
	if resp.ContentLength > 0 {
		zipSize = uint64(resp.ContentLength)
	}

	// The zip and the staged binary both live next to the binary, so one
	// filesystem has to hold both at once.
	if err := room.ensure(binDir, zipSize+binEstimate+updateMargin); err != nil {
		return "", err
	}
	workDir := updateWorkDir(target)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return "", fmt.Errorf("work dir: %w", spaceHint(err, binDir))
	}
	defer os.RemoveAll(workDir)

	zipPath := filepath.Join(workDir, "release.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("temp file: %w", spaceHint(err, binDir))
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", fmt.Errorf("save download: %w", spaceHint(err, binDir))
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("save download: %w", spaceHint(err, binDir))
	}

	// Write straight to <binary>.new: no second copy, so the update needs
	// one binary's worth of space less than extracting to a temp dir first.
	staged := target + ".new"
	if err := extractBinary(zipPath, staged, func(size uint64) error {
		return room.ensure(binDir, size+updateMargin)
	}); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("replace binary: %w", err)
	}
	log.Infof("control: installed %s at %s", tag, target)
	if note := room.cleaned.String(); note != "" {
		return tag + " (" + note + ")", nil
	}
	return tag, nil
}

// extractBinary writes the zip's v2node entry to dest. fits is told the
// uncompressed size first, so a full disk is reported as such before any
// byte is written.
func extractBinary(zipPath, dest string, fits func(size uint64) error) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	for _, entry := range reader.File {
		name := filepath.Base(entry.Name)
		if name != "v2node" || entry.FileInfo().IsDir() {
			continue
		}
		if err := fits(entry.UncompressedSize64); err != nil {
			return err
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("read zip entry: %w", err)
		}
		defer rc.Close()
		dst, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("stage binary: %w", spaceHint(err, filepath.Dir(dest)))
		}
		// Bounded copy: a release binary is tens of megabytes, not gigabytes.
		if _, err := io.Copy(dst, io.LimitReader(rc, 512<<20)); err != nil {
			dst.Close()
			return fmt.Errorf("stage binary: %w", spaceHint(err, filepath.Dir(dest)))
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("stage binary: %w", spaceHint(err, filepath.Dir(dest)))
		}
		return nil
	}
	return fmt.Errorf("zip has no v2node binary")
}

// spaceHint turns a raw ENOSPC into the same readable message as the
// up-front check, in case the disk filled up while the update ran.
func spaceHint(err error, dir string) error {
	if err == nil || !errors.Is(err, syscall.ENOSPC) {
		return err
	}
	free, _ := freeBytes(dir)
	return fmt.Errorf("disk full: %d MB free on %s; free space then retry", free/mb, dir)
}

// scheduleRestart hands the process back to the service manager shortly after
// the HTTP answer has been flushed.
func scheduleRestart() {
	go func() {
		time.Sleep(time.Second)
		if path, err := exec.LookPath("systemctl"); err == nil {
			if err := exec.Command(path, "restart", "v2node").Start(); err == nil {
				return
			}
		}
		log.Warn("control: systemctl unavailable, exiting so the supervisor restarts v2node")
		os.Exit(0)
	}()
}
