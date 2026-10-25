// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditSchemaVersion is the "schema" field of every event. It goes up when
// the fields of an existing event change (docs/audit-schema.md).
const auditSchemaVersion = 2

// errAuditUnavailable is returned by Event while the journal is
// unavailable: nothing that depends on the record may go ahead.
var errAuditUnavailable = errors.New("audit journal unavailable")

// Logger appends JSONL events to the broker journal. Every event is
// written and fsynced before Event returns, so a caller that answers the
// client after Event never answers ahead of the record. A failed write or
// fsync makes the journal unavailable: the broker then refuses new
// connections (audit_unavailable), and events go to stderr instead (the
// reserve) until a reopen on SIGHUP succeeds.
type Logger struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	down   error     // non-nil: the journal is unavailable, and why
	stderr io.Writer // the reserve; os.Stderr outside tests

	// test seams for write and fsync failures; nil means the file's own
	write func(f *os.File, p []byte) (int, error)
	sync  func(f *os.File) error
}

// eventHook, when set (tests), sees every event before it is written.
var eventHook func(event string, fields map[string]any)

// NewLogger opens the log owner-only: events carry request argv and env,
// which may hold secrets. The modes apply only when the broker creates them.
func NewLogger(path string) (*Logger, error) {
	f, err := openJournal(path)
	if err != nil {
		return nil, err
	}
	return &Logger{path: path, f: f, stderr: os.Stderr}, nil
}

func openJournal(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := endPartialLine(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// endPartialLine closes a line a failed write (or a crash) left without its
// newline, so the next event starts a line of its own and stays parseable:
// the fragment is one bad line, not glued to the next event.
func endPartialLine(f *os.File) error {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, st.Size()-1); err != nil {
		return fmt.Errorf("journal tail: %w", err)
	}
	if last[0] == '\n' {
		return nil
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("journal tail: %w", err)
	}
	return f.Sync()
}

// Event writes one JSONL line and fsyncs it. Map keys are marshaled
// sorted, so lines are stable. A nil error means the event is on disk;
// otherwise the journal is unavailable and the line went to stderr.
func (l *Logger) Event(event string, fields map[string]any) error {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["schema"] = auditSchemaVersion
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = event
	if eventHook != nil {
		eventHook(event, fields)
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	line := append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down != nil {
		l.reserve(line)
		return errAuditUnavailable
	}
	if err := l.append(line); err != nil {
		l.fail(err)
		l.reserve(line)
		return errAuditUnavailable
	}
	return nil
}

func (l *Logger) append(line []byte) error {
	write, sync := l.write, l.sync
	if write == nil {
		write = (*os.File).Write
	}
	if sync == nil {
		sync = (*os.File).Sync
	}
	if _, err := write(l.f, line); err != nil {
		return fmt.Errorf("journal write: %w", err)
	}
	if err := sync(l.f); err != nil {
		return fmt.Errorf("journal fsync: %w", err)
	}
	return nil
}

// fail marks the journal unavailable (l.mu held) and says why on stderr,
// as a line for the operator and an audit_unavailable event.
func (l *Logger) fail(err error) {
	l.down = err
	fmt.Fprintf(l.stderr, "tmb-broker: journal unavailable, refusing new requests until a reopen succeeds (SIGHUP): %v\n", err)
	l.stderrEvent("audit_unavailable", map[string]any{"pid": os.Getpid(), "path": l.path, "error": err.Error()})
}

// stderrEvent writes an event to stderr only (l.mu held).
func (l *Logger) stderrEvent(event string, fields map[string]any) {
	fields["schema"] = auditSchemaVersion
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = event
	if eventHook != nil {
		eventHook(event, fields)
	}
	if b, err := json.Marshal(fields); err == nil {
		l.reserve(append(b, '\n'))
	}
}

// reserve writes a journal line to stderr (l.mu held).
func (l *Logger) reserve(line []byte) {
	_, _ = l.stderr.Write(line)
}

// Unavailable returns why the journal is unavailable, nil when it works.
func (l *Logger) Unavailable() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.down
}

// Reopen opens the journal path again (SIGHUP, after logrotate moved the
// file) and swaps the new file in. Success also ends an unavailable state.
// Failure makes the journal unavailable: the old file may be renamed or
// deleted, so the broker does not keep writing into it.
func (l *Logger) Reopen() error {
	f, err := openJournal(l.path)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		err = fmt.Errorf("journal reopen: %w", err)
		l.fail(err)
		return err
	}
	old := l.f
	l.f = f
	if l.down != nil {
		fmt.Fprintf(l.stderr, "tmb-broker: journal %s reopened, accepting requests again\n", l.path)
		l.down = nil
	}
	return old.Close()
}

// Close closes the journal; a later event goes to stderr only.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down == nil {
		l.down = errJournalClosed
	}
	l.f.Close()
}

var errJournalClosed = errors.New("journal closed")

// Path returns the journal path.
func (l *Logger) Path() string { return l.path }
