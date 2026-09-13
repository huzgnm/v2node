package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// add runs the merge with the flags a panel install command would pass.
func add(t *testing.T, path string, nodeID int, apiKey, _ string) error {
	t.Helper()
	addConfigPath = path
	addAPIHost = "https://mosvpn.com"
	addNodeID = nodeID
	addAPIKey = apiKey
	addTimeout = 15

	return nodeAddHandle(nil, nil)
}

func readDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	return doc
}

func nodesOf(t *testing.T, path string) []any {
	t.Helper()
	nodes, ok := readDoc(t, path)["Nodes"].([]any)
	if !ok {
		t.Fatalf("Nodes is not a list")
	}
	return nodes
}

// FK-1: a Nodes key of the wrong shape must stop the command, not be treated as
// an empty list — that silently deleted every node already on the machine.
func TestRefusesAConfigWhoseNodesKeyIsNotAList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := `{"Nodes":{"a":{"NodeID":61,"ApiKey":"CU"}}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := add(t, path, 62, "NEW", "s62"); err == nil {
		t.Fatal("want an error for a Nodes object")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != original {
		t.Fatalf("the config must be untouched, got %s", raw)
	}
	if _, err := os.Stat(path + ".mosvpn.tmp"); !os.IsNotExist(err) {
		t.Fatal("a temp file was left behind")
	}
}

// FK-2: a hand-quoted "NodeID" is still that node; starting it twice is the
// failure this guards against.
func TestMatchesANodeIdWrittenAsAString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"Nodes":[{"NodeID":"61","ApiKey":"OLD","Timeout":90}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := add(t, path, 61, "NEW", "s61"); err != nil {
		t.Fatal(err)
	}

	nodes := nodesOf(t, path)
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	node := nodes[0].(map[string]any)
	if node["ApiKey"] != "NEW" {
		t.Fatalf("the existing node must be updated, got %v", node["ApiKey"])
	}
}

// FK-3: the file holds the ApiKey and the control secret, so writing it must not
// relax the mode the operator chose.
func TestKeepsTheConfigFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"Nodes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := add(t, path, 61, "K", "s61"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600 kept, got %04o", info.Mode().Perm())
	}

	// A config this command creates itself is not world-readable either.
	fresh := filepath.Join(dir, "fresh.json")
	if err := add(t, fresh, 62, "K", "s62"); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("a new config must be 0600, got %04o", info.Mode().Perm())
	}
}

// FK-4: re-running the install command must not throw away what the operator
// tuned by hand on that node.
func TestReRunKeepsHandTunedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	existing := `{"Nodes":[{"NodeID":61,"ApiKey":"OLD","Timeout":90,"CustomSetting":"quan-trong",` +
		`"RetryCount":7}]}`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := add(t, path, 61, "NEW", "s61"); err != nil {
		t.Fatal(err)
	}

	node := nodesOf(t, path)[0].(map[string]any)
	if node["Timeout"].(float64) != 90 {
		t.Fatalf("Timeout must survive, got %v", node["Timeout"])
	}
	if node["CustomSetting"] != "quan-trong" {
		t.Fatalf("extra keys must survive, got %v", node["CustomSetting"])
	}
	if node["ApiKey"] != "NEW" {
		t.Fatalf("ApiKey must be updated, got %v", node["ApiKey"])
	}
	if node["RetryCount"].(float64) != 7 {
		t.Fatalf("other keys must survive, got %v", node["RetryCount"])
	}
}

func TestAddsASecondNodeWithoutLosingTheFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := add(t, path, 61, "K", "s61"); err != nil {
		t.Fatal(err)
	}
	if err := add(t, path, 62, "K", "s62"); err != nil {
		t.Fatal(err)
	}

	nodes := nodesOf(t, path)
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	ids := map[float64]bool{}
	for _, entry := range nodes {
		ids[entry.(map[string]any)["NodeID"].(float64)] = true
	}
	if !ids[61] || !ids[62] {
		t.Fatalf("both nodes must be present, got %v", ids)
	}
}
