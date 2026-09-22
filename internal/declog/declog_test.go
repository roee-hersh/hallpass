package declog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.now = func() time.Time { return time.Unix(0, 0) }
	l.Log(Entry{Connection: "c", User: "u@x", Action: "a", Resource: "r:1", Decision: "allow", Code: "allowed"})
	l.Log(Entry{Connection: "c", User: "u@x", Action: "a", Resource: "r:1", Decision: "deny", Code: "denied"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Decision != "allow" || e.Time.Unix() != 0 {
		t.Fatalf("%+v", e)
	}
}

func TestOpenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "decisions.log")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Entry{Decision: "unknown"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"decision":"unknown"`) {
		t.Fatalf("%s", b)
	}
	for _, name := range []string{"", "none", "stderr", "stdout"} {
		if _, err := Open(name); err != nil {
			t.Errorf("Open(%q): %v", name, err)
		}
	}
	var nilLogger *Logger
	nilLogger.Log(Entry{})
}
