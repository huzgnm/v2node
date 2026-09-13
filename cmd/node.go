package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// One machine commonly serves several nodes from one config, and the panel hands
// out one install command per node. Writing the config from scratch each time
// would drop every node installed before, so adding a node merges into the
// existing file instead. It lives here, in the agent, because the installer
// cannot assume jq or python exist on a fresh VPS.
var (
	addConfigPath   string
	addAPIHost      string
	addNodeID       int
	addAPIKey       string
	addTimeout      int
	addControlListn string
	addControlSecre string
)

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
	f.StringVar(&addControlListn, "control-listen", "", "MosVPN control listen address")
	f.StringVar(&addControlSecre, "control-secret", "", "MosVPN control secret")

	nodeCommand.AddCommand(&nodeAddCommand)
	command.AddCommand(&nodeCommand)
}

func nodeAddHandle(_ *cobra.Command, _ []string) error {
	if addAPIHost == "" || addNodeID <= 0 || addAPIKey == "" {
		return fmt.Errorf("--api-host, --node-id and --api-key are required")
	}

	doc := map[string]any{}
	raw, err := os.ReadFile(addConfigPath)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", addConfigPath, err)
		}
	case os.IsNotExist(err):
		doc["Log"] = map[string]any{"Level": "warning", "Output": "", "Access": "none"}
	default:
		return fmt.Errorf("read %s: %w", addConfigPath, err)
	}

	entry := map[string]any{
		"ApiHost": addAPIHost,
		"NodeID":  addNodeID,
		"ApiKey":  addAPIKey,
		"Timeout": addTimeout,
	}
	if addControlSecre != "" {
		control := map[string]any{"Secret": addControlSecre}
		if addControlListn != "" {
			control["Listen"] = addControlListn
		}
		entry["Control"] = control
	}

	nodes, _ := doc["Nodes"].([]any)
	replaced := false
	for i, existing := range nodes {
		node, ok := existing.(map[string]any)
		if !ok {
			continue
		}
		id, ok := node["NodeID"].(float64)
		if !ok || int(id) != addNodeID {
			continue
		}
		// Re-running the same install command must be a no-op, not a duplicate
		// entry: two entries for one node would start it twice.
		nodes[i] = entry
		replaced = true
		break
	}
	if !replaced {
		nodes = append(nodes, entry)
	}
	doc["Nodes"] = nodes

	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp := addConfigPath + ".mosvpn.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, addConfigPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", addConfigPath, err)
	}

	action := "added"
	if replaced {
		action = "updated"
	}
	fmt.Printf("node %d %s in %s (%d node(s) total)\n", addNodeID, action, addConfigPath, len(nodes))

	return nil
}
