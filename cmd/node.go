package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// One machine commonly serves several nodes from one config, and the panel hands
// out one install command per node. Writing the config from scratch each time
// would drop every node installed before, so adding a node merges into the
// existing file instead. It lives here, in the agent, because the installer
// cannot assume jq or python exist on a fresh VPS.
var (
	addConfigPath string
	addAPIHost    string
	addNodeID     int
	addAPIKey     string
	addTimeout    int
)

// The mode a freshly created config gets: it holds the panel ApiKey, so it is
// not world-readable.
const newConfigMode = os.FileMode(0o600)

var nodeCommand = cobra.Command{
	Use:   "node",
	Short: "Manage the nodes in the config file",
}

var nodeAddCommand = cobra.Command{
	Use:   "add",
	Short: "Add a node to the config file, replacing one with the same NodeID",
	RunE:  nodeAddHandle,
	Args:  cobra.NoArgs,
}

func init() {
	f := nodeAddCommand.Flags()
	f.StringVarP(&addConfigPath, "config", "c", "/etc/v2node/config.json", "config file path")
	f.StringVar(&addAPIHost, "api-host", "", "panel URL")
	f.IntVar(&addNodeID, "node-id", 0, "node id")
	f.StringVar(&addAPIKey, "api-key", "", "panel api key")
	f.IntVar(&addTimeout, "timeout", 15, "request timeout")

	nodeCommand.AddCommand(&nodeAddCommand)
	command.AddCommand(&nodeCommand)
}

func nodeAddHandle(_ *cobra.Command, _ []string) error {
	if addAPIHost == "" || addNodeID <= 0 || addAPIKey == "" {
		return fmt.Errorf("--api-host, --node-id and --api-key are required")
	}

	doc := map[string]any{}
	mode := newConfigMode
	raw, err := os.ReadFile(addConfigPath)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", addConfigPath, err)
		}
		// Keep whatever mode the operator gave the file. Writing a temp file and
		// renaming it would otherwise silently relax 0600 to 0644 on a file that
		// holds the ApiKey and the control secret.
		if info, err := os.Stat(addConfigPath); err == nil {
			mode = info.Mode().Perm()
		}
	case os.IsNotExist(err):
		doc["Log"] = map[string]any{"Level": "warning", "Output": "", "Access": "none"}
	default:
		return fmt.Errorf("read %s: %w", addConfigPath, err)
	}

	nodes, err := nodeList(doc)
	if err != nil {
		return err
	}

	updated := false
	for i, existing := range nodes {
		node, ok := existing.(map[string]any)
		if !ok || !sameNodeID(node["NodeID"], addNodeID) {
			continue
		}
		// Re-running the same install command must update this node in place,
		// not replace the whole entry: anything the operator tuned by hand
		// (Timeout, extra keys) has to survive.
		applyNode(node)
		nodes[i] = node
		updated = true
		break
	}
	if !updated {
		entry := map[string]any{"Timeout": addTimeout}
		applyNode(entry)
		nodes = append(nodes, entry)
	}
	doc["Nodes"] = nodes

	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp := addConfigPath + ".mosvpn.tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	// WriteFile only applies the mode when it creates the file, so an earlier
	// interrupted run could leave a temp file with the wrong mode behind.
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, addConfigPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", addConfigPath, err)
	}

	action := "added"
	if updated {
		action = "updated"
	}
	fmt.Printf("node %d %s in %s (%d node(s) total)\n", addNodeID, action, addConfigPath, len(nodes))

	return nil
}

// nodeList returns the existing Nodes array. A Nodes key of the wrong shape is
// an error rather than an empty list: treating it as empty would silently
// discard every node already installed on this machine.
func nodeList(doc map[string]any) ([]any, error) {
	raw, present := doc["Nodes"]
	if !present || raw == nil {
		return nil, nil
	}
	nodes, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("config key \"Nodes\" is %T, not a list; refusing to touch it", raw)
	}

	return nodes, nil
}

// sameNodeID compares ids across the shapes a hand-edited config can hold: JSON
// numbers decode to float64, but an operator may well have quoted the value, and
// treating "61" as a different node would start node 61 twice.
func sameNodeID(value any, want int) bool {
	switch v := value.(type) {
	case float64:
		return int(v) == want
	case int:
		return v == want
	case json.Number:
		if parsed, err := strconv.Atoi(v.String()); err == nil {
			return parsed == want
		}
	case string:
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed == want
		}
	}

	return false
}

// applyNode writes the fields this command owns, leaving every other key alone.
func applyNode(node map[string]any) {
	node["ApiHost"] = addAPIHost
	node["NodeID"] = addNodeID
	node["ApiKey"] = addAPIKey
	if _, ok := node["Timeout"]; !ok {
		node["Timeout"] = addTimeout
	}
}
