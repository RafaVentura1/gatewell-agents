package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	log := NewLogger()
	log.Infof("Gatewell agent %s starting on %s.", AgentVersion, osType())

	if !isStamped() {
		log.Warnf("ORG_ID placeholder was not replaced at build time — " +
			"enrollment will be rejected by the platform.")
	}

	identity, err := LoadIdentity(log)
	if err != nil {
		log.Errorf("Fatal: %v", err)
		os.Exit(1)
	}

	api := NewAPI(identity, log)
	events := NewEventBuffer(log)
	telemetryBuf := NewTelemetryBuffer()
	collector := NewCollector(telemetryBuf, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sig
		log.Infof("Received %v, shutting down.", s)
		cancel()
	}()

	agent := &Agent{
		id:        identity,
		api:       api,
		events:    events,
		telemetry: telemetryBuf,
		collector: collector,
		log:       log,
		handled:   make(map[string]struct{}),
	}

	agent.enroll(ctx)
	agent.run(ctx)

	log.Infof("Gatewell agent stopped.")
}

// Agent owns the runtime loops.
type Agent struct {
	id        *Identity
	api       *API
	events    *EventBuffer
	telemetry *TelemetryBuffer
	collector *Collector
	log       *Logger

	mu      sync.Mutex
	handled map[string]struct{}
}

// ---- enrollment ------------------------------------------------------------

func (a *Agent) enroll(ctx context.Context) {
	if a.id.HasToken() {
		a.log.Infof("Existing API token found, skipping enrollment.")
		return
	}

	backoff := 5 * time.Second

	for ctx.Err() == nil && !a.id.HasToken() {
		resp, err := a.api.Checkin(ctx, true)

		switch {
		case err != nil:
			a.log.Warnf("Enrollment check-in failed: %v", err)

		case resp.Status == "rate_limited":
			a.log.Warnf("Enrollment rate limited, waiting %ds.", resp.RetryAfterSeconds)
			if !sleepCtx(ctx, time.Duration(resp.RetryAfterSeconds)*time.Second) {
				return
			}
			continue

		case resp.APIToken != "":
			a.id.StoreToken(resp.APIToken, a.log)
			a.id.SetPolicyVersion(resp.PolicyVersion, a.log)
			a.events.Add("agent_enrolled", "info",
				"Agent enrolled successfully as device "+a.id.DeviceID+".")
			a.log.Infof("Enrollment complete.")
			return

		default:
			// Server accepted the check-in but issued no token, meaning the
			// device is already enrolled and holds a token we cannot read.
			a.log.Warnf("Check-in succeeded without a token. Retrying.")
		}

		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

// ---- loops -----------------------------------------------------------------

func (a *Agent) run(ctx context.Context) {
	var wg sync.WaitGroup

	loops := []struct {
		name     string
		interval time.Duration
		fn       func(context.Context)
	}{
		{"heartbeat", heartbeatInterval, a.heartbeat},
		{"poll", pollInterval, a.poll},
		{"events", eventFlushInterval, a.flushEvents},
		{"telemetry-sample", telemetrySampleInterval, func(context.Context) { a.collector.Sample() }},
		{"telemetry-flush", telemetryFlushInterval, a.flushTelemetry},
	}

	for _, l := range loops {
		wg.Add(1)
		go func(name string, interval time.Duration, fn func(context.Context)) {
			defer wg.Done()
			a.loop(ctx, name, interval, fn)
		}(l.name, l.interval, l.fn)
	}

	wg.Wait()
}

// loop runs fn on an interval and treats every failure as recoverable. A panic
// in one loop is contained rather than taking the daemon down.
func (a *Agent) loop(
	ctx context.Context, name string, interval time.Duration, fn func(context.Context),
) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.log.Warnf("Loop %s recovered from panic: %v", name, r)
				}
			}()
			fn(ctx)
		}()

		if !sleepCtx(ctx, interval) {
			return
		}
	}
}

// ---- 2b heartbeat ----------------------------------------------------------

func (a *Agent) heartbeat(ctx context.Context) {
	resp, err := a.api.Checkin(ctx, false)
	if err != nil {
		a.log.Warnf("Heartbeat failed: %v", err)
		return
	}

	if resp.Status == "rate_limited" {
		a.log.Warnf("Heartbeat rate limited, waiting %ds.", resp.RetryAfterSeconds)
		sleepCtx(ctx, time.Duration(resp.RetryAfterSeconds)*time.Second)
		return
	}

	// A token may be reissued on any check-in.
	if resp.APIToken != "" && resp.APIToken != a.id.Token() {
		a.id.StoreToken(resp.APIToken, a.log)
		a.log.Infof("API token rotated.")
	}

	if resp.PolicyVersion != "" && resp.PolicyVersion != a.id.PolicyVersion() {
		a.log.Infof("Server policy_version %s differs from local %s; "+
			"expecting sync_policy on next poll.",
			resp.PolicyVersion, a.id.PolicyVersion())
	}
}

// ---- 2c poll + dispatch ----------------------------------------------------

func (a *Agent) poll(ctx context.Context) {
	cmds, err := a.api.PollCommands(ctx)
	if err != nil {
		a.log.Debugf("Poll failed: %v", err)
		return
	}

	for _, cmd := range cmds {
		if ctx.Err() != nil {
			return
		}
		if cmd.ID != "" && a.alreadyHandled(cmd.ID) {
			continue
		}

		switch cmd.CommandType {
		case "run_script":
			a.handleRunScript(ctx, cmd)
		case "sync_policy":
			a.handleSyncPolicy(cmd)
		default:
			a.log.Infof("Ignoring unknown command type %q.", cmd.CommandType)
			a.events.Add("unknown_command", "info",
				"Received unsupported command type '"+cmd.CommandType+"'.")
		}
	}
}

func (a *Agent) handleRunScript(ctx context.Context, cmd AgentCommand) {
	var p struct {
		Content     string `json:"content"`
		ScriptRunID string `json:"script_run_id"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		a.log.Warnf("run_script payload unreadable: %v", err)
		return
	}
	if p.Content == "" || p.ScriptRunID == "" {
		a.log.Warnf("run_script missing content or script_run_id.")
		return
	}

	a.log.Infof("Executing script run %s.", p.ScriptRunID)
	outcome := RunScript(ctx, p.Content, a.log)

	a.api.ReportScriptResult(ctx, p.ScriptRunID, outcome.ExitCode, outcome.OutputLog)

	severity := "info"
	if outcome.ExitCode != 0 {
		severity = "warning"
	}
	a.events.Add("script_executed", severity,
		"Script run "+p.ScriptRunID+" finished with exit code "+itoa(outcome.ExitCode)+".")
}

func (a *Agent) handleSyncPolicy(cmd AgentCommand) {
	var p struct {
		PolicyVersion string `json:"policy_version"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil || p.PolicyVersion == "" {
		return
	}

	a.id.SetPolicyVersion(p.PolicyVersion, a.log)
	a.log.Infof("Policy version set to %s.", p.PolicyVersion)
	a.events.Add("policy_synced", "info",
		"Policy version updated to "+p.PolicyVersion+".")
}

func (a *Agent) alreadyHandled(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, seen := a.handled[id]; seen {
		return true
	}
	if len(a.handled) > 5000 {
		a.handled = make(map[string]struct{})
	}
	a.handled[id] = struct{}{}
	return false
}

// ---- 2d event flush --------------------------------------------------------

func (a *Agent) flushEvents(ctx context.Context) {
	a.events.LogDropStats()

	for a.events.Len() > 0 && ctx.Err() == nil {
		batch := a.events.TakeBatch()
		if len(batch) == 0 {
			return
		}
		if !a.api.SendEvents(ctx, batch) {
			a.events.Requeue(batch) // retry on the next tick
			return
		}
	}
}

// ---- 2e telemetry flush ----------------------------------------------------

func (a *Agent) flushTelemetry(ctx context.Context) {
	for _, telemetryType := range a.telemetry.PendingTypes() {
		for ctx.Err() == nil {
			batch := a.telemetry.TakeBatch(telemetryType)
			if len(batch) == 0 {
				break
			}

			// One batch_id per batch, reused across retries inside
			// SendTelemetry so retries are never double-counted.
			batchID, err := newUUID()
			if err != nil {
				a.telemetry.Requeue(telemetryType, batch)
				return
			}

			if !a.api.SendTelemetry(ctx, telemetryType, batchID, batch) {
				a.telemetry.Requeue(telemetryType, batch)
				break
			}
		}
	}
}
