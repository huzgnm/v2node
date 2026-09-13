// Package control carries out the commands the panel hands a node.
//
// The panel never dials a node. The agent already posts telemetry every 30
// seconds, and the panel answers that post with whatever it wants this node to
// do, so a node needs no inbound port, no certificate, no domain and no address
// the panel has to know. Commands arrive over the same authenticated channel the
// node already uses for its config, and nothing new has to be provisioned.
package control

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// Command is one instruction from the panel.
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	NodeID  int    `json:"node_id"`
	ApiHost string `json:"api_host"`
	ApiKey  string `json:"api_key"`
	Ref     string `json:"ref"`
}

// Result is what the agent reports back.
type Result struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// Set when this process must be replaced to finish the command. The caller
	// has to deliver the result BEFORE restarting: the next beat is 30 seconds
	// away and this process does not live that long, so a result left for it is
	// simply lost. That asymmetry is worse than it sounds — a failed update does
	// not restart and so does report, meaning the operator only ever saw
	// failures and never a success.
	RestartAfter bool `json:"-"`
}

// Restart hands the process back to the service manager. Exported so the caller
// can report first and restart second.
func Restart() {
	scheduleRestart()
}

// Apply runs one command and describes what happened. A command never aborts the
// agent: a node that fails to update must keep serving customers and keep
// reporting, so every failure comes back as a Result instead.
func Apply(cmd Command, configPath string, nodeID int) Result {
	out := Result{ID: cmd.ID, Type: cmd.Type}
	log.Infof("control: applying command %s (%s)", cmd.Type, cmd.ID)

	switch cmd.Type {
	case "reconfig":
		id := cmd.NodeID
		if id == 0 {
			id = nodeID
		}
		if cmd.ApiHost == "" && cmd.ApiKey == "" {
			out.Detail = "nothing to apply"
			return out
		}
		applied, err := rewriteNodeConfig(configPath, id, cmd.ApiHost, cmd.ApiKey)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		// The file watcher reloads the node from the new config; no restart.
		out.OK = true
		out.Detail = fmt.Sprintf("applied %v", applied)

	case "update":
		ref := cmd.Ref
		if ref == "" {
			ref = "latest"
		}
		// The ref reaches a download URL on a root-run agent, so it is checked
		// here too and not only in the panel.
		if !refPattern.MatchString(ref) {
			out.Detail = "invalid ref"
			return out
		}
		tag, err := selfUpdate(ref)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		out.OK = true
		out.Detail = "installed " + tag
		out.RestartAfter = true

	case "restart":
		out.OK = true
		out.Detail = "restarting"
		out.RestartAfter = true

	default:
		out.Detail = "unknown command"
	}

	return out
}
