package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canary = "CANARY-SECRET-0f9d2a"

func TestParseRejectsInline(t *testing.T) {
	for _, in := range []string{"", "hunter2", "token:abc", "ENV:X"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted an inline value", in)
		}
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("HALLPASS_TEST_SECRET", canary)
	s, err := Parse("env:HALLPASS_TEST_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetString()
	if err != nil || got != canary {
		t.Fatalf("got %q, %v", got, err)
	}
	if s.Ref() != "env:HALLPASS_TEST_SECRET" {
		t.Errorf("Ref = %q", s.Ref())
	}
	os.Unsetenv("HALLPASS_TEST_SECRET")
	if _, err := s.Get(); err == nil {
		t.Error("expected error for unset variable")
	}
}

func TestFileRereadAndTrim(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := MustParse("file:" + p)
	got, err := s.GetString()
	if err != nil || got != canary {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := os.WriteFile(p, []byte(canary+"-rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetString()
	if got != canary+"-rotated" {
		t.Fatalf("file secret not re-read: %q", got)
	}
}

func TestNeverPrints(t *testing.T) {
	s := Literal(canary)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("x", "secret", s, "ptr", &s)
	outputs := []string{
		s.String(),
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%s", s), fmt.Sprintf("%q", s),
		fmt.Sprintf("%v", &s), fmt.Sprintf("%+v", struct{ S Secret }{s}),
		buf.String(),
	}
	if b, err := json.Marshal(map[string]any{"s": s, "p": &s}); err != nil {
		t.Fatal(err)
	} else {
		outputs = append(outputs, string(b))
	}
	for i, o := range outputs {
		if strings.Contains(o, canary) {
			t.Errorf("output %d leaked the secret: %s", i, o)
		}
	}
	if _, err := (Secret{}).Get(); err != ErrEmpty {
		t.Errorf("zero Get = %v", err)
	}
}
