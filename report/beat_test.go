package report

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/control"
)

// fakePanel answers each beat with the next scripted batch of commands and
// records the command_result every beat carried.
type fakePanel struct {
	mu      sync.Mutex
	replies [][]panel.MosvpnCommand
	fail    map[int]bool // beat index (0-based) to answer with 500
	results []string     // command_result id per beat, "" when none
}

func (f *fakePanel) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.results)
	var body struct {
		CommandResult *control.Result `json:"command_result"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id := ""
	if body.CommandResult != nil {
		id = body.CommandResult.ID
	}
	f.results = append(f.results, id)
	if f.fail[n] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var cmds []panel.MosvpnCommand
	if len(f.replies) > 0 {
		cmds, f.replies = f.replies[0], f.replies[1:]
	}
	_ = json.NewEncoder(w).Encode(panel.MosvpnStatusReply{Commands: cmds})
}

func setup(t *testing.T, f *fakePanel) (*panel.Client, conf.NodeConfig, *int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	zero := 0
	node := conf.NodeConfig{APIHost: srv.URL, NodeID: 7, Key: "k", Timeout: 5, RetryCount: &zero}
	client, err := panel.New(&node)
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	old := restartAgent
	restartAgent = func() { restarts++ }
	t.Cleanup(func() { restartAgent = old })
	return client, node, &restarts
}

// Unknown command types make Apply return a result without touching the host.
func cmd(id string) panel.MosvpnCommand { return panel.MosvpnCommand{ID: id, Type: "noop-" + id} }

func sameSeq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("beats carried %q, want %q", got, want)
	}
}

func TestResultIsReportedOnTheSameTick(t *testing.T) {
	f := &fakePanel{replies: [][]panel.MosvpnCommand{{cmd("a")}}}
	client, node, _ := setup(t, f)
	pending := map[int][]*control.Result{}
	if !beat(client, payload{NodeID: 7}, node, "", pending) {
		t.Fatal("unexpected restart")
	}
	sameSeq(t, f.results, "", "a")
	if len(pending) != 0 {
		t.Fatalf("pending left: %v", pending)
	}
}

func TestTwoCommandsInOneReplyBothReported(t *testing.T) {
	f := &fakePanel{replies: [][]panel.MosvpnCommand{{cmd("a"), cmd("b")}}}
	client, node, _ := setup(t, f)
	pending := map[int][]*control.Result{}
	beat(client, payload{NodeID: 7}, node, "", pending)
	sameSeq(t, f.results, "", "a", "b")
}

func TestCommandArrivingOnAnExtraBeatIsCarriedOut(t *testing.T) {
	f := &fakePanel{replies: [][]panel.MosvpnCommand{{cmd("a")}, {cmd("c")}}}
	client, node, _ := setup(t, f)
	pending := map[int][]*control.Result{}
	beat(client, payload{NodeID: 7}, node, "", pending)
	sameSeq(t, f.results, "", "a", "c")
}

func TestRestartReportsEverythingFirst(t *testing.T) {
	f := &fakePanel{replies: [][]panel.MosvpnCommand{{cmd("a"), {ID: "r", Type: "restart"}, cmd("late")}}}
	client, node, restarts := setup(t, f)
	pending := map[int][]*control.Result{}
	if beat(client, payload{NodeID: 7}, node, "", pending) {
		t.Fatal("expected restart")
	}
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
	sameSeq(t, f.results, "", "a", "r")
}

func TestFailedExtraBeatKeepsResultForNextTick(t *testing.T) {
	f := &fakePanel{
		replies: [][]panel.MosvpnCommand{{cmd("a")}},
		fail:    map[int]bool{1: true},
	}
	client, node, _ := setup(t, f)
	pending := map[int][]*control.Result{}
	beat(client, payload{NodeID: 7}, node, "", pending)
	if len(pending[7]) != 1 || pending[7][0].ID != "a" {
		t.Fatalf("pending = %v", pending)
	}
	// Next tick delivers it once, then stops.
	beat(client, payload{NodeID: 7}, node, "", pending)
	sameSeq(t, f.results, "", "a", "a")
	if len(pending) != 0 {
		t.Fatalf("pending left: %v", pending)
	}
}

func TestBeatsPerTickAreBounded(t *testing.T) {
	var replies [][]panel.MosvpnCommand
	for i := 0; i < 50; i++ {
		replies = append(replies, []panel.MosvpnCommand{cmd(fmt.Sprint(i))})
	}
	f := &fakePanel{replies: replies}
	client, node, _ := setup(t, f)
	pending := map[int][]*control.Result{}
	beat(client, payload{NodeID: 7}, node, "", pending)
	if len(f.results) != maxBeatsPerTick {
		t.Fatalf("sent %d beats, want %d", len(f.results), maxBeatsPerTick)
	}
	if len(pending[7]) != 1 {
		t.Fatalf("last result should wait for the next tick, pending = %d", len(pending[7]))
	}
}
