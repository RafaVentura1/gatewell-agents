package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ScriptOutcome is what gets reported back to agentScriptResult.
type ScriptOutcome struct {
	ExitCode  int
	OutputLog string
}

// RunScript writes the payload to a mode-0700 temp file, executes it under
// bash as the daemon user (root), captures combined stdout+stderr, and always
// removes the temp file.
func RunScript(ctx context.Context, content string, log *Logger) ScriptOutcome {
	tmp := filepath.Join(os.TempDir(),
		fmt.Sprintf("gw_%d.sh", time.Now().UnixNano()))

	if err := os.WriteFile(tmp, []byte(content), 0o700); err != nil {
		return ScriptOutcome{ExitCode: -2, OutputLog: "[error] write temp: " + err.Error()}
	}
	defer os.Remove(tmp)

	runCtx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "/bin/bash", tmp)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()

	exitCode := 0
	switch {
	case err == nil:
		// success

	case runCtx.Err() == context.DeadlineExceeded:
		exitCode = -1
		out.WriteString(fmt.Sprintf("\n[timeout] exceeded %s", scriptTimeout))

	default:
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -2
			out.WriteString("\n[error] " + err.Error())
		}
	}

	log.Infof("Script finished with exit code %d.", exitCode)
	return ScriptOutcome{ExitCode: exitCode, OutputLog: out.String()}
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}
