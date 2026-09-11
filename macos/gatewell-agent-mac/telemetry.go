package main

import (
	"time"
)

// procInfo is the platform-independent shape a collector returns.
type procInfo struct {
	PID       int
	PPID      int
	Name      string
	Path      string
	CmdLine   string
	StartedAt time.Time
}

// connInfo describes one established outbound connection.
type connInfo struct {
	PID        int
	Name       string
	Local      string
	RemoteIP   string
	RemotePort int
}

// Collector samples the host periodically and diffs against the previous
// snapshot, so only new activity is emitted. Sampling rather than event-driven
// capture keeps the footprint small; eBPF (Linux) and EndpointSecurity (macOS)
// are the phase-2 upgrade.
//
// Platform implementations live in collector_darwin.go and collector_linux.go.
type Collector struct {
	buf *TelemetryBuffer
	log *Logger

	knownPIDs  map[int]struct{}
	knownConns map[string]struct{}
	primed     bool
}

func NewCollector(buf *TelemetryBuffer, log *Logger) *Collector {
	return &Collector{
		buf:        buf,
		log:        log,
		knownPIDs:  make(map[int]struct{}),
		knownConns: make(map[string]struct{}),
	}
}

// Sample runs one collection pass. It never panics and never returns an error:
// a collector failing on an unusual host must not take the agent down.
func (c *Collector) Sample() {
	defer func() {
		if r := recover(); r != nil {
			c.log.Warnf("telemetry sample recovered: %v", r)
		}
	}()

	c.sampleProcesses()
	c.sampleConnections()
	c.primed = true
}

func (c *Collector) sampleProcesses() {
	procs, err := listProcesses()
	if err != nil {
		c.log.Debugf("process listing failed: %v", err)
		return
	}

	current := make(map[int]struct{}, len(procs))
	for _, p := range procs {
		current[p.PID] = struct{}{}

		if !c.primed {
			continue
		}
		if _, seen := c.knownPIDs[p.PID]; seen {
			continue
		}

		id, err := newUUID()
		if err != nil {
			continue
		}

		c.buf.Add("process", map[string]any{
			"event_id":     id,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"kind":         "process_start",
			"pid":          p.PID,
			"parent_pid":   p.PPID,
			"name":         p.Name,
			"path":         p.Path,
			"command_line": truncate(p.CmdLine, 2048),
		})
	}

	c.knownPIDs = current
}

func (c *Collector) sampleConnections() {
	conns, err := listConnections()
	if err != nil {
		c.log.Debugf("connection listing failed: %v", err)
		return
	}

	current := make(map[string]struct{}, len(conns))
	for _, cn := range conns {
		key := connKey(cn)
		current[key] = struct{}{}

		if !c.primed {
			continue
		}
		if _, seen := c.knownConns[key]; seen {
			continue
		}

		id, err := newUUID()
		if err != nil {
			continue
		}

		c.buf.Add("network", map[string]any{
			"event_id":     id,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"kind":         "tcp_connect",
			"pid":          cn.PID,
			"process_name": cn.Name,
			"local":        cn.Local,
			"remote_ip":    cn.RemoteIP,
			"remote_port":  cn.RemotePort,
		})
	}

	c.knownConns = current
}

func connKey(c connInfo) string {
	return itoa(c.PID) + "|" + c.RemoteIP + ":" + itoa(c.RemotePort)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
