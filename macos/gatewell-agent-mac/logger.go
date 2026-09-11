package main

import (
	"log"
	"os"
)

// Logger writes to stdout/stderr. launchd redirects to
// /var/log/gatewell-agent.log on macOS; systemd captures it into journald on
// Linux. Callers must never pass the API token, enrollment token, or ORG_ID
// into a log message.
type Logger struct {
	debug bool
	out   *log.Logger
	err   *log.Logger
}

func NewLogger() *Logger {
	flags := log.Ldate | log.Ltime | log.LUTC
	return &Logger{
		debug: os.Getenv("GATEWELL_DEBUG") == "1",
		out:   log.New(os.Stdout, "gatewell-agent ", flags),
		err:   log.New(os.Stderr, "gatewell-agent ", flags),
	}
}

func (l *Logger) Debugf(format string, v ...any) {
	if l.debug {
		l.out.Printf("[debug] "+format, v...)
	}
}

func (l *Logger) Infof(format string, v ...any)  { l.out.Printf("[info]  "+format, v...) }
func (l *Logger) Warnf(format string, v ...any)  { l.err.Printf("[warn]  "+format, v...) }
func (l *Logger) Errorf(format string, v ...any) { l.err.Printf("[error] "+format, v...) }
