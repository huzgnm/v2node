// Package report sends host telemetry (CPU, RAM, disk, network) from the node
// to the MosVPN panel, which paints it onto the admin node table.
//
// Field shape follows Xboard's machine "status" report so an agent or panel
// already speaking that dialect needs no new serialiser:
//
//	{ node_id, token, cpu, mem:{total,used}, swap:{total,used},
//	  disk:{total,used}, net:{in_speed,out_speed} }
//
// It goes through the same panel client the agent uses for every other call, so
// authentication, retry and timeout are whatever the node is already configured
// with, and nothing new has to be provisioned. The panel answers each beat with
// the commands it wants this node to run, which is why the node needs no inbound
// port.
package report

import (
	"net"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/control"
)

const interval = 30 * time.Second

type netSample struct {
	at  time.Time
	in  uint64
	out uint64
}

type sizePair struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type netPair struct {
	InSpeed  float64 `json:"in_speed"`
	OutSpeed float64 `json:"out_speed"`
}

// commandResult is the outcome of the command the panel handed over on an
// earlier beat; it rides along with the next report.
type payload struct {
	NodeID int      `json:"node_id"`
	Token  string   `json:"token"`
	CPU    float64  `json:"cpu"`
	Mem    sizePair `json:"mem"`
	Swap   sizePair `json:"swap"`
	Disk   sizePair `json:"disk"`
	Net    *netPair `json:"net,omitempty"`
	// The panel is reached through a relay, so the address it sees a request
	// come from is not this machine's. Report the egress address so the admin
	// list shows the real machine.
	IP            string          `json:"ip,omitempty"`
	CommandResult *control.Result `json:"command_result,omitempty"`
}

// Start begins reporting in the background. The config file is re-read every
// cycle so a reconfig (new ApiHost/ApiKey) takes effect without a restart.
func Start(configPath string) {
	go loop(configPath)
}

func loop(configPath string) {
	// Prime the CPU counter: without a first call the next reading is 0.
	_, _ = cpu.Percent(0, false)
	var prev *netSample
	// Outcome of the last command, reported on the next beat.
	pending := map[int]*control.Result{}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		c := conf.New()
		if err := c.LoadFromPath(configPath); err != nil {
			log.WithField("err", err).Debug("report: reload config failed")
			continue
		}
		body, next := collect(prev)
		prev = next
		for i := range c.NodeConfigs {
			node := c.NodeConfigs[i]
			if node.APIHost == "" || node.Key == "" {
				continue
			}
			client, err := panel.New(&node)
			if err != nil {
				log.WithField("err", err).Debug("report: client failed")
				continue
			}
			body.NodeID = node.NodeID
			body.Token = node.Key
			body.CommandResult = pending[node.NodeID]

			reply, err := client.ReportMosvpnStatus(body, node.MosvpnKey)
			if err != nil {
				log.WithField("err", err).Debug("report: send failed")
				continue
			}
			// The panel accepted the result, so stop repeating it.
			delete(pending, node.NodeID)

			for _, cmd := range reply.Commands {
				result := control.Apply(control.Command(cmd), configPath, node.NodeID)
				pending[node.NodeID] = &result
				if !result.RestartAfter {
					continue
				}
				// This process is about to be replaced, so send the result now
				// instead of leaving it for a beat that will never run here.
				body.CommandResult = &result
				if _, err := client.ReportMosvpnStatus(body, node.MosvpnKey); err != nil {
					log.WithField("err", err).Warn("report: could not deliver command result before restart")
				}
				control.Restart()
				return
			}
		}
	}
}

// egressIP is this host's own address on the route out, read from the kernel's
// routing choice rather than from an external "what is my IP" service: no
// network traffic leaves the box, and nothing depends on a third party being up.
// A UDP "connection" performs no handshake, so the peer address is never
// contacted. On a NAT'd host this is a private address; the panel drops
// anything that is not public, so such a node simply reports none.
func egressIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	if addr.IP.IsLoopback() || addr.IP.IsPrivate() || addr.IP.IsLinkLocalUnicast() {
		return ""
	}
	return addr.IP.String()
}

func collect(prev *netSample) (payload, *netSample) {
	var out payload
	out.IP = egressIP()

	if values, err := cpu.Percent(0, false); err == nil && len(values) > 0 {
		out.CPU = values[0]
	}
	if out.CPU < 0 {
		out.CPU = 0
	}
	if out.CPU > 100 {
		out.CPU = 100
	}

	if v, err := mem.VirtualMemory(); err == nil && v != nil {
		out.Mem = sizePair{Total: v.Total, Used: v.Used}
	}
	if s, err := mem.SwapMemory(); err == nil && s != nil {
		out.Swap = sizePair{Total: s.Total, Used: s.Used}
	}
	if d, err := disk.Usage("/"); err == nil && d != nil {
		out.Disk = sizePair{Total: d.Total, Used: d.Used}
	}

	now := time.Now()
	var current *netSample
	if counters, err := psnet.IOCounters(false); err == nil && len(counters) > 0 {
		current = &netSample{at: now, in: counters[0].BytesRecv, out: counters[0].BytesSent}
		// Speed is a delta over the elapsed window. A counter reset (reboot,
		// interface flap) shows as a decrease and is skipped rather than
		// reported as an enormous spike.
		if prev != nil {
			seconds := current.at.Sub(prev.at).Seconds()
			if seconds > 0 && current.in >= prev.in && current.out >= prev.out {
				out.Net = &netPair{
					InSpeed:  float64(current.in-prev.in) / seconds,
					OutSpeed: float64(current.out-prev.out) / seconds,
				}
			}
		}
	}
	return out, current
}
