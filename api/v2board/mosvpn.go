package panel

import (
	"fmt"
)

// MosVPN host telemetry, sent the same way this agent calls every other panel
// API: through the shared client, which already carries node_type / node_id /
// token and the configured retry and timeout. Nothing new is provisioned and
// nothing new has to be authenticated.
//
// The reply is also how the panel gives this node work. Answering the heartbeat
// with pending commands means a node needs no inbound port, no certificate and
// no address the panel has to know.
const mosvpnStatusPath = "/api/v1/guest/mosvpn/node/stats"

// MosvpnCommand is one instruction the panel wants this node to carry out.
type MosvpnCommand struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	NodeID  int    `json:"node_id"`
	ApiHost string `json:"api_host"`
	ApiKey  string `json:"api_key"`
	Ref     string `json:"ref"`
}

// MosvpnStatusReply is the panel's answer to one heartbeat.
type MosvpnStatusReply struct {
	Commands []MosvpnCommand `json:"commands"`
}

// ReportMosvpnStatus posts one telemetry beat and returns the commands the panel
// handed back. A panel without the MosVPN module simply answers with none.
func (c *Client) ReportMosvpnStatus(body any, nodeKey string) (*MosvpnStatusReply, error) {
	reply := &MosvpnStatusReply{}
	r, err := c.client.
		R().
		SetHeader("X-Mosvpn-Node-Key", nodeKey).
		SetBody(body).
		SetResult(reply).
		ForceContentType("application/json").
		Post(mosvpnStatusPath)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.StatusCode() < 200 || r.StatusCode() >= 300 {
		return nil, fmt.Errorf("received status code: %d", r.StatusCode())
	}

	return reply, nil
}
