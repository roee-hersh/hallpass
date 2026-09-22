// Package declog writes the decision log: one JSON object per line for every
// answered /check request. It is the audit trail.
package declog

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one logged decision.
type Entry struct {
	Time       time.Time `json:"time"`
	Connection string    `json:"connection"`
	User       string    `json:"user"`
	Groups     []string  `json:"groups,omitempty"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	Decision   string    `json:"decision"`
	Code       string    `json:"code"`
	Reason     string    `json:"reason"`
	Cached     bool      `json:"cached"`
	DurationMS int64     `json:"duration_ms"`
	Status     int       `json:"status"`
	Remote     string    `json:"remote,omitempty"`
}

// Logger writes entries. It is safe for concurrent use.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	c   io.Closer
	now func() time.Time
}

// New writes to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w, now: time.Now}
}

// Open creates a Logger on a path. "stderr" and "stdout" name the standard
// streams; "" or "none" discards entries.
func Open(path string) (*Logger, error) {
	switch path {
	case "", "none":
		return New(io.Discard), nil
	case "stderr":
		return New(os.Stderr), nil
	case "stdout":
		return New(os.Stdout), nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := New(f)
	l.c = f
	return l, nil
}

// Log writes one entry. Time is filled in when zero.
func (l *Logger) Log(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	_, _ = l.w.Write(b)
	l.mu.Unlock()
}

// Close closes an underlying file, if any.
func (l *Logger) Close() error {
	if l == nil || l.c == nil {
		return nil
	}
	return l.c.Close()
}
