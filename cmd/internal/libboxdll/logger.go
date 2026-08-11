package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const logFileName = "libboxdll.log"

type fileLogger struct {
	mu   sync.Mutex
	path string
}

var dllLogger fileLogger

// configure places the persistent DLL log beside the runtime working files.
// Until setup supplies a working directory, log entries use the OS temp path.
func (l *fileLogger) configure(workingPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if workingPath == "" {
		workingPath = os.TempDir()
	}
	if err := os.MkdirAll(workingPath, 0o755); err != nil {
		return err
	}
	l.path = filepath.Join(workingPath, logFileName)
	return nil
}

func (l *fileLogger) currentPath() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		return filepath.Join(os.TempDir(), logFileName)
	}
	return l.path
}

func (l *fileLogger) write(scope, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [libboxdll] [%s] %s\n", time.Now().Format(time.RFC3339Nano), scope, message)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Always print to stderr as well as persisting the same line. This makes the
	// DLL trace visible in an attached debugger without changing the Dart ABI.
	_, _ = fmt.Fprint(os.Stderr, line)
	path := l.path
	if path == "" {
		path = filepath.Join(os.TempDir(), logFileName)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s [libboxdll] [logger] create log directory failed: %v\n", time.Now().Format(time.RFC3339Nano), err)
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s [libboxdll] [logger] open %s failed: %v\n", time.Now().Format(time.RFC3339Nano), path, err)
		return
	}
	_, writeErr := file.WriteString(line)
	closeErr := file.Close()
	if writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s [libboxdll] [logger] write %s failed: %v\n", time.Now().Format(time.RFC3339Nano), path, writeErr)
	} else if closeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s [libboxdll] [logger] close %s failed: %v\n", time.Now().Format(time.RFC3339Nano), path, closeErr)
	}
}

func tracef(scope, format string, args ...any) {
	dllLogger.write(scope, format, args...)
}

func traceResult(scope, value string) string {
	if value == "" {
		tracef(scope, "completed successfully")
	} else {
		tracef(scope, "completed with result: %s", value)
	}
	return value
}
