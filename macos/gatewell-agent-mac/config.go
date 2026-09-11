package main

import (
	"runtime"
	"strings"
	"time"
)

// Stamped at build time:
//
//	go build -ldflags "-X main.OrgID=<id> -X main.EnrollmentToken=<tok>"
//
// Left as placeholders so an unstamped local build is obvious rather than
// silently enrolling against the wrong org.
var (
	OrgID           = "__ORG_ID__"
	EnrollmentToken = "__ENROLLMENT_TOKEN__"
)

const (
	APIBase      = "https://gatewell-329446a6.base44.app/functions"
	AgentVersion = "1.0.0"

	heartbeatInterval       = 60 * time.Second
	pollInterval            = 30 * time.Second
	eventFlushInterval      = 60 * time.Second
	telemetrySampleInterval = 15 * time.Second
	telemetryFlushInterval  = 120 * time.Second
	scriptTimeout           = 30 * time.Minute
	httpTimeout             = 30 * time.Second

	// Server-enforced batch caps.
	maxEventsPerBatch    = 100
	maxTelemetryPerBatch = 200

	// Local buffer caps so an unreachable platform can never exhaust memory.
	eventBufferCapacity     = 5000
	telemetryBufferCapacity = 4000
)

// osType is reported to the platform as "macos" or "linux".
func osType() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return "linux"
}

// isStamped reports whether CI replaced the build-time placeholders.
func isStamped() bool {
	return !strings.HasPrefix(OrgID, "__")
}
