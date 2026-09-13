// Package report sends host telemetry (CPU, RAM, disk, network) from the node
// to the MosVPN panel, which paints it onto the admin node table.
//
// Field shape follows Xboard's machine "status" report so an agent or panel
// already speaking that dialect needs no new serialiser:
//
//	{ node_id, token, cpu, mem:{total,used}, swap:{total,used},
//	  disk:{total,used}, net:{in_speed,out_speed} }
//
// Authentication is the same shared server token the node already uses to pull
// its config, so nothing new has to be provisioned.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

const (
	interval = 30 * time.Second
	endpoint = "/api/v1/guest/mosvpn/node/stats"
)

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

type payload struct {
	NodeID int      `json:"node_id"`
	Token  string   `json:"token"`
	CPU    float64  `json:"cpu"`
	Mem    sizePair `json:"mem"`
	Swap   sizePair `json:"swap"`
	Disk   sizePair `json:"disk"`
	Net    *netPair `json:"net,omitempty"`
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
			body.NodeID = node.NodeID
			body.Token = node.Key
			if err := post(node.APIHost, body); err != nil {
				log.WithField("err", err).Debug("report: send failed")
			}
		}
	}
}

func collect(prev *netSample) (payload, *netSample) {
	var out payload

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

func post(apiHost string, body payload) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(apiHost, "/") + endpoint
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("stats http %d", resp.StatusCode)
	}
	return nil
}
