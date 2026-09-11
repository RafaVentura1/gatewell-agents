//go:build darwin

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// listProcesses uses ps, which reads the same libproc data the Endpoint
// Security framework exposes, without requiring the ES entitlement. Phase 2
// replaces this with a real ES client subscribed to ES_EVENT_TYPE_NOTIFY_EXEC.
func listProcesses() ([]procInfo, error) {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,comm=,args=").Output()
	if err != nil {
		return nil, err
	}

	var procs []procInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])

		path := fields[2]
		name := path
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			name = path[idx+1:]
		}

		cmdline := ""
		if len(fields) > 3 {
			cmdline = strings.Join(fields[3:], " ")
		}

		procs = append(procs, procInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    name,
			Path:    path,
			CmdLine: cmdline,
		})
	}
	return procs, nil
}

// listConnections uses lsof for PID-attributed TCP connections. Sampled, and
// limited to established outbound sockets to keep the volume down.
func listConnections() ([]connInfo, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-FpcnT").Output()
	if err != nil {
		// lsof exits non-zero when it has partial access; parse what we got.
		if len(out) == 0 {
			return nil, err
		}
	}

	var (
		conns   []connInfo
		curPID  int
		curName string
	)

	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		tag, value := line[0], line[1:]

		switch tag {
		case 'p':
			curPID, _ = strconv.Atoi(value)
		case 'c':
			curName = value
		case 'n':
			local, remote, ok := splitConnection(value)
			if !ok {
				continue
			}
			ip, port, ok := splitHostPort(remote)
			if !ok {
				continue
			}
			conns = append(conns, connInfo{
				PID:        curPID,
				Name:       curName,
				Local:      local,
				RemoteIP:   ip,
				RemotePort: port,
			})
		}
	}
	return conns, nil
}

// splitConnection parses lsof's "local->remote" name field.
func splitConnection(s string) (local, remote string, ok bool) {
	parts := strings.Split(s, "->")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func splitHostPort(s string) (host string, port int, ok bool) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:idx], p, true
}
