//go:build linux

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listProcesses reads /proc directly — no shelling out, no dependencies.
// Phase 2 replaces this with eBPF or auditd for true exec events.
func listProcesses() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []procInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		base := filepath.Join("/proc", e.Name())

		name, ppid := readStat(filepath.Join(base, "stat"))
		if name == "" {
			continue
		}

		path, _ := os.Readlink(filepath.Join(base, "exe"))
		cmdline := readCmdline(filepath.Join(base, "cmdline"))

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

// readStat pulls comm and ppid out of /proc/<pid>/stat. comm is wrapped in
// parentheses and may itself contain spaces, so we split on the last ')'.
func readStat(path string) (name string, ppid int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0
	}
	s := string(b)

	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close < open {
		return "", 0
	}

	name = s[open+1 : close]

	rest := strings.Fields(s[close+1:])
	if len(rest) >= 2 {
		ppid, _ = strconv.Atoi(rest[1])
	}
	return name, ppid
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// listConnections parses /proc/net/tcp and maps socket inodes back to PIDs via
// /proc/<pid>/fd. This is the netlink-equivalent without a dependency.
func listConnections() ([]connInfo, error) {
	inodeToConn, err := parseProcNetTCP("/proc/net/tcp")
	if err != nil {
		return nil, err
	}

	inodeToPID, pidNames := mapSocketInodes()

	var conns []connInfo
	for inode, c := range inodeToConn {
		pid, ok := inodeToPID[inode]
		if !ok {
			continue
		}
		c.PID = pid
		c.Name = pidNames[pid]
		conns = append(conns, c)
	}
	return conns, nil
}

// parseProcNetTCP returns established connections keyed by socket inode.
func parseProcNetTCP(path string) (map[string]connInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const stateEstablished = "01"

	out := make(map[string]connInfo)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != stateEstablished {
			continue
		}

		localIP, localPort, ok := parseHexAddr(fields[1])
		if !ok {
			continue
		}
		remoteIP, remotePort, ok := parseHexAddr(fields[2])
		if !ok || remoteIP == "0.0.0.0" {
			continue
		}

		out[fields[9]] = connInfo{
			Local:      fmt.Sprintf("%s:%d", localIP, localPort),
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}
	}
	return out, scanner.Err()
}

// parseHexAddr decodes the little-endian "AABBCCDD:PORT" form used by /proc.
func parseHexAddr(s string) (ip string, port int, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0, false
	}

	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, false
	}
	// Little-endian: reverse to dotted quad.
	addr := net.IPv4(raw[3], raw[2], raw[1], raw[0])

	p, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	return addr.String(), int(p), true
}

// mapSocketInodes walks /proc/<pid>/fd looking for socket:[inode] symlinks.
func mapSocketInodes() (map[string]int, map[int]string) {
	inodeToPID := make(map[string]int)
	pidNames := make(map[int]string)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeToPID, pidNames
	}

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or not ours to read
		}

		name, _ := readStat(filepath.Join("/proc", e.Name(), "stat"))
		pidNames[pid] = name

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodeToPID[link[8:len(link)-1]] = pid
			}
		}
	}
	return inodeToPID, pidNames
}
