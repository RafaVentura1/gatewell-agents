package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Identity owns the machine-scoped state: a stable device_id, the API token
// issued at enrollment, and the last known policy version.
//
// Paths follow the platform conventions:
//
//	device_id  /etc/gatewell/device_id                       (0600, root)
//	token      darwin: /Library/Application Support/Gatewell/api_token
//	           linux:  /etc/gatewell/api_token               (0600, root)
//
// The token value is never written to a log.
type Identity struct {
	mu sync.RWMutex

	DeviceID  string
	Hostname  string
	OSVersion string

	token         string
	policyVersion string
}

const configDir = "/etc/gatewell"

func tokenDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Gatewell"
	}
	return configDir
}

func deviceIDPath() string     { return filepath.Join(configDir, "device_id") }
func tokenPath() string        { return filepath.Join(tokenDir(), "api_token") }
func policyVersionPath() string { return filepath.Join(configDir, "policy_version") }

// LoadIdentity reads existing state or creates it on first run.
func LoadIdentity(log *Logger) (*Identity, error) {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", configDir, err)
	}
	if err := os.MkdirAll(tokenDir(), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", tokenDir(), err)
	}

	id := &Identity{
		Hostname:  hostname(),
		OSVersion: osVersion(),
	}

	if v := readTrimmed(deviceIDPath()); v != "" {
		id.DeviceID = v
	} else {
		generated, err := newUUID()
		if err != nil {
			return nil, fmt.Errorf("generate device_id: %w", err)
		}
		if err := writeSecret(deviceIDPath(), generated); err != nil {
			return nil, fmt.Errorf("persist device_id: %w", err)
		}
		id.DeviceID = generated
		log.Infof("Generated new device_id.")
	}

	id.token = readTrimmed(tokenPath())
	id.policyVersion = readTrimmed(policyVersionPath())
	if id.policyVersion == "" {
		id.policyVersion = "0"
	}

	log.Infof("Identity ready. device_id=%s host=%s os=%s token_present=%t",
		id.DeviceID, id.Hostname, id.OSVersion, id.token != "")

	return id, nil
}

func (i *Identity) Token() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.token
}

func (i *Identity) HasToken() bool { return i.Token() != "" }

// StoreToken persists the token with root-only permissions. The value is
// deliberately never included in the log line.
func (i *Identity) StoreToken(token string, log *Logger) {
	if strings.TrimSpace(token) == "" {
		return
	}
	if err := writeSecret(tokenPath(), token); err != nil {
		log.Errorf("Failed to persist API token: %v", err)
		return
	}
	i.mu.Lock()
	i.token = token
	i.mu.Unlock()
	log.Infof("API token stored.")
}

func (i *Identity) PolicyVersion() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.policyVersion
}

func (i *Identity) SetPolicyVersion(v string, log *Logger) {
	if strings.TrimSpace(v) == "" {
		return
	}
	if err := writeSecret(policyVersionPath(), v); err != nil {
		log.Warnf("Failed to persist policy_version: %v", err)
	}
	i.mu.Lock()
	i.policyVersion = v
	i.mu.Unlock()
}

// ---- helpers ---------------------------------------------------------------

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeSecret(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func osVersion() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
		return "darwin"
	}

	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return "linux"
}

func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "0.0.0.0"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP.String()
			}
		}
	}
	return "0.0.0.0"
}
