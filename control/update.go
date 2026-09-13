package control

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

// selfUpdate downloads the release binary for ref and swaps it in. The caller
// restarts the service afterwards so the new binary takes over.
func selfUpdate(ref string) (string, error) {
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

	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/v2node-linux-%s.zip", releaseRepo, tag, arch)
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

	tmpDir, err := os.MkdirTemp("", "v2node-update")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "release.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return "", fmt.Errorf("save download: %w", err)
	}
	f.Close()

	binary, err := extractBinary(zipPath, tmpDir)
	if err != nil {
		return "", err
	}

	target, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	staged := target + ".new"
	if err := copyFile(binary, staged, 0o755); err != nil {
		return "", fmt.Errorf("stage binary: %w", err)
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("replace binary: %w", err)
	}
	log.Infof("control: installed %s at %s", tag, target)
	return tag, nil
}

func extractBinary(zipPath, destDir string) (string, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	for _, entry := range reader.File {
		name := filepath.Base(entry.Name)
		if name != "v2node" || entry.FileInfo().IsDir() {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("read zip entry: %w", err)
		}
		out := filepath.Join(destDir, "v2node")
		dst, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			rc.Close()
			return "", fmt.Errorf("write binary: %w", err)
		}
		// Bounded copy: a release binary is tens of megabytes, not gigabytes.
		if _, err := io.Copy(dst, io.LimitReader(rc, 512<<20)); err != nil {
			rc.Close()
			dst.Close()
			return "", fmt.Errorf("extract binary: %w", err)
		}
		rc.Close()
		dst.Close()
		return out, nil
	}
	return "", fmt.Errorf("zip has no v2node binary")
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
