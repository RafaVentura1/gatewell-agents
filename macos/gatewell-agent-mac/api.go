package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AgentCommand is one entry from agentPollCommands.
type AgentCommand struct {
	ID          string          `json:"id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
}

// CheckinResponse is the agentCheckin reply for both enrollment and heartbeat.
type CheckinResponse struct {
	Status            string `json:"status"`
	PolicyVersion     string `json:"policy_version"`
	APIToken          string `json:"api_token"`
	TokenIssued       bool   `json:"token_issued"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// API wraps every platform call. Nothing here panics and nothing returns a
// fatal error to the caller — the agent must survive the platform being
// unreachable indefinitely.
type API struct {
	client *http.Client
	id     *Identity
	log    *Logger
}

func NewAPI(id *Identity, log *Logger) *API {
	return &API{
		client: &http.Client{Timeout: httpTimeout},
		id:     id,
		log:    log,
	}
}

// ---- 2a / 2b : agentCheckin ------------------------------------------------

// Checkin performs enrollment (enrolling=true, sends enrollment_token, no
// Bearer) or a heartbeat (enrolling=false, sends Bearer, omits the token).
func (a *API) Checkin(ctx context.Context, enrolling bool) (*CheckinResponse, error) {
	body := map[string]any{
		"device_id":              a.id.DeviceID,
		"org_id":                 OrgID,
		"hostname":               a.id.Hostname,
		"os_type":                osType(),
		"os_version":             a.id.OSVersion,
		"agent_version":          AgentVersion,
		"ip_address":             localIP(),
		"policy_version_current": a.id.PolicyVersion(),
	}
	if enrolling {
		body["enrollment_token"] = EnrollmentToken
	}

	raw, status, err := a.post(ctx, "agentCheckin", body, !enrolling)
	if err != nil {
		return nil, err
	}

	var out CheckinResponse

	// Decode is best-effort and only meaningful for JSON bodies. A proxy or
	// gateway in front of the platform can return an HTML error page, so the
	// status code is authoritative and is checked first — otherwise a 502 is
	// reported as an unhelpful JSON decode failure.
	if isJSON(raw) {
		_ = json.Unmarshal(raw, &out)
	}

	if status == http.StatusTooManyRequests {
		if out.RetryAfterSeconds <= 0 {
			out.RetryAfterSeconds = 60
		}
		out.Status = "rate_limited"
		return &out, nil
	}

	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("checkin http %d", status)
	}

	if !isJSON(raw) {
		return nil, fmt.Errorf("checkin returned non-JSON body (%d bytes)", len(raw))
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode checkin: %w", err)
	}
	return &out, nil
}

// isJSON reports whether the body plausibly starts a JSON object or array,
// so an HTML or plaintext error page is never fed to the decoder.
func isJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// ---- 2c : agentPollCommands ------------------------------------------------

func (a *API) PollCommands(ctx context.Context) ([]AgentCommand, error) {
	url := fmt.Sprintf("%s/agentPollCommands?device_id=%s", APIBase, a.id.DeviceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	a.addAuth(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("poll http %d", resp.StatusCode)
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	if !isJSON(raw) {
		return nil, fmt.Errorf("poll returned non-JSON body (%d bytes)", len(raw))
	}

	var cmds []AgentCommand
	if err := json.Unmarshal(raw, &cmds); err != nil {
		return nil, fmt.Errorf("decode commands: %w", err)
	}
	return cmds, nil
}

// ---- 2c : agentScriptResult ------------------------------------------------

func (a *API) ReportScriptResult(
	ctx context.Context, scriptRunID string, exitCode int, output string,
) bool {
	return a.postWithRetry(ctx, "agentScriptResult", map[string]any{
		"script_run_id": scriptRunID,
		"device_id":     a.id.DeviceID,
		"exit_code":     exitCode,
		"output_log":    truncate(output, 64*1024),
	})
}

// ---- 2d : agentEvents ------------------------------------------------------

func (a *API) SendEvents(ctx context.Context, batch []map[string]any) bool {
	if len(batch) == 0 {
		return true
	}
	return a.postWithRetry(ctx, "agentEvents", map[string]any{
		"device_id": a.id.DeviceID,
		"batch":     batch,
	})
}

// ---- 2e : agentTelemetry ---------------------------------------------------

// SendTelemetry posts one batch. batchID is the idempotency key: the caller
// generates it once and this function reuses the same value across all retry
// attempts so a retried POST is never double-counted server side.
func (a *API) SendTelemetry(
	ctx context.Context, telemetryType, batchID string, batch []map[string]any,
) bool {
	if len(batch) == 0 {
		return true
	}
	return a.postWithRetry(ctx, "agentTelemetry", map[string]any{
		"device_id":      a.id.DeviceID,
		"telemetry_type": telemetryType,
		"batch_id":       batchID,
		"batch":          batch,
	})
}

// ---- internals -------------------------------------------------------------

func (a *API) addAuth(req *http.Request) {
	if t := a.id.Token(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

func (a *API) post(
	ctx context.Context, fn string, body map[string]any, auth bool,
) ([]byte, int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, APIBase+"/"+fn, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GatewellAgent/"+AgentVersion+" ("+osType()+")")
	if auth {
		a.addAuth(req)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// postWithRetry makes up to three attempts with exponential backoff, honouring
// retry_after_seconds on 429. Returns false rather than an error so callers can
// simply requeue the batch.
func (a *API) postWithRetry(ctx context.Context, fn string, body map[string]any) bool {
	delay := 2 * time.Second

	for attempt := 1; attempt <= 3; attempt++ {
		raw, status, err := a.post(ctx, fn, body, true)

		switch {
		case err != nil:
			a.log.Debugf("%s attempt %d failed: %v", fn, attempt, err)

		case status >= 200 && status < 300:
			return true

		case status == http.StatusTooManyRequests:
			wait := 60
			var parsed struct {
				RetryAfterSeconds int `json:"retry_after_seconds"`
			}
			if json.Unmarshal(raw, &parsed) == nil && parsed.RetryAfterSeconds > 0 {
				wait = parsed.RetryAfterSeconds
			}
			a.log.Warnf("%s rate limited, waiting %ds.", fn, wait)
			if !sleepCtx(ctx, time.Duration(wait)*time.Second) {
				return false
			}
			continue

		case status >= 400 && status < 500:
			// Not retryable.
			a.log.Warnf("%s rejected with http %d.", fn, status)
			return false

		default:
			a.log.Debugf("%s http %d, attempt %d.", fn, status, attempt)
		}

		if attempt < 3 {
			if !sleepCtx(ctx, delay) {
				return false
			}
			delay *= 2
		}
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[...truncated]"
}
