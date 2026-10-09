// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger appends JSONL events to the broker log.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

func NewLogger(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

// Event writes one JSONL line. Map keys are marshaled sorted -> stable.
func (l *Logger) Event(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = event
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.f.Write(append(b, '\n'))
}

func (l *Logger) Close() { l.f.Close() }
