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

// fakePanel stands in for one node's panel endpoint: it answers each beat with
// the next scripted batch of commands and records the command_result each beat
// carried, as "id" or "id(detail)" for skipped ones.
type fakePanel struct {
	mu      sync.Mutex
	replies [][]panel.MosvpnCommand
	fail    map[int]bool // beat index (0-based) to answer with 500
	results []string     // per beat, "" when it carried no result
	url     string
}

func (f *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.results)
	var body struct {
		CommandResult *control.Result `json:"command_result"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	got := ""
	if res := body.CommandResult; res != nil {
		got = res.ID
		if res.Detail == skippedDetail {
			got += "(skipped)"
		}
	}
	f.results = append(f.results, got)
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

func newPanel(t *testing.T, replies ...[]panel.MosvpnCommand) *fakePanel {
	t.Helper()
	f := &fakePanel{replies: replies, fail: map[int]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func nodeAt(f *fakePanel, id int) conf.NodeConfig {
	zero := 0
	return conf.NodeConfig{APIHost: f.url, NodeID: id, Key: "k", Timeout: 5, RetryCount: &zero}
}

// countRestarts swaps the restart out so tests never restart the test binary.
func countRestarts(t *testing.T) *int {
	t.Helper()
	n := 0
	old := restartAgent
	restartAgent = func() { n++ }
	t.Cleanup(func() { restartAgent = old })
	return &n
}

// Unknown command types make Apply return a result without touching the host.
func noop(id string) panel.MosvpnCommand { return panel.MosvpnCommand{ID: id, Type: "noop-" + id} }

func restartCmd(id string) panel.MosvpnCommand { return panel.MosvpnCommand{ID: id, Type: "restart"} }

func sameSeq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("beats carried %q, want %q", got, want)
	}
}

func TestResultIsReportedOnTheSameTick(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{noop("a")})
	pending := map[int][]*control.Result{}
	if !tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", pending) {
		t.Fatal("unexpected restart")
	}
	sameSeq(t, f.results, "", "a")
	if len(pending) != 0 {
		t.Fatalf("pending left: %v", pending)
	}
}

func TestTwoCommandsInOneReplyBothReported(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{noop("a"), noop("b")})
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{})
	sameSeq(t, f.results, "", "a", "b")
}

func TestCommandArrivingOnAnExtraBeatIsCarriedOut(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{noop("a")}, []panel.MosvpnCommand{noop("c")})
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{})
	sameSeq(t, f.results, "", "a", "c")
}

func TestRestartReportsBeforeRestarting(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{noop("a"), restartCmd("r")})
	restarts := countRestarts(t)
	if tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{}) {
		t.Fatal("expected restart")
	}
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
	sameSeq(t, f.results, "", "a", "r")
}

// QA-5: a command queued after restart in the same reply used to be lost.
func TestCommandAfterRestartInSameReplyStillRuns(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{restartCmd("r"), noop("b")})
	restarts := countRestarts(t)
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{})
	sameSeq(t, f.results, "", "b", "r")
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
}

func TestSecondRestartInSameReplyIsSkipped(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{restartCmd("r1"), restartCmd("r2")})
	restarts := countRestarts(t)
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{})
	sameSeq(t, f.results, "", "r1", "r2(skipped)")
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
}

// QA-6: one agent serves every node on the machine, so a restart must first
// deliver the other nodes' pending results.
func TestRestartFlushesOtherNodesPendingResults(t *testing.T) {
	a := newPanel(t)
	a.fail[0] = true // A's tick beat fails, so its old result stays pending
	b := newPanel(t, []panel.MosvpnCommand{restartCmd("r")})
	restarts := countRestarts(t)
	pending := map[int][]*control.Result{1: {{ID: "old", Type: "noop"}}}
	tick([]conf.NodeConfig{nodeAt(a, 1), nodeAt(b, 2)}, payload{}, "", pending)
	sameSeq(t, a.results, "old", "old")
	sameSeq(t, b.results, "", "r")
	if *restarts != 1 {
		t.Fatalf("restarts = %d", *restarts)
	}
}

func TestCommandHandedOverWhileFlushingIsAnsweredSkipped(t *testing.T) {
	f := newPanel(t,
		[]panel.MosvpnCommand{restartCmd("r")},
		[]panel.MosvpnCommand{noop("x")}, // reply to the beat carrying r
	)
	countRestarts(t)
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", map[int][]*control.Result{})
	sameSeq(t, f.results, "", "r", "x(skipped)")
}

func TestFailedExtraBeatKeepsResultForNextTick(t *testing.T) {
	f := newPanel(t, []panel.MosvpnCommand{noop("a")})
	f.fail[1] = true
	nodes := []conf.NodeConfig{nodeAt(f, 7)}
	pending := map[int][]*control.Result{}
	tick(nodes, payload{}, "", pending)
	if len(pending[7]) != 1 || pending[7][0].ID != "a" {
		t.Fatalf("pending = %v", pending)
	}
	// Next tick delivers it once, then stops.
	tick(nodes, payload{}, "", pending)
	sameSeq(t, f.results, "", "a", "a")
	if len(pending) != 0 {
		t.Fatalf("pending left: %v", pending)
	}
}

func TestBeatsPerTickAreBounded(t *testing.T) {
	var replies [][]panel.MosvpnCommand
	for i := 0; i < 50; i++ {
		replies = append(replies, []panel.MosvpnCommand{noop(fmt.Sprint(i))})
	}
	f := newPanel(t, replies...)
	pending := map[int][]*control.Result{}
	tick([]conf.NodeConfig{nodeAt(f, 7)}, payload{}, "", pending)
	if len(f.results) != maxBeatsPerTick {
		t.Fatalf("sent %d beats, want %d", len(f.results), maxBeatsPerTick)
	}
	if len(pending[7]) != 1 {
		t.Fatalf("last result should wait for the next tick, pending = %d", len(pending[7]))
	}
}
