package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func call(p string) Call { return Call{Method: "GET", Path: p, Status: 200} }

func TestRecorder(t *testing.T) {
	ctx, rec := WithRecorder(context.Background())
	if rec.Evidence() != nil {
		t.Fatal("empty recorder has evidence")
	}
	RecorderFrom(ctx).Record(Call{Method: "GET", Path: "/a", Status: 200, ETag: `"1"`})
	ev := rec.Evidence()
	if ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Path != "/a" || ev.Truncated() {
		t.Fatalf("%+v", ev.Calls())
	}
	// The snapshot does not change under later records.
	RecorderFrom(ctx).Record(call("/b"))
	if len(ev.Calls()) != 1 || len(rec.Evidence().Calls()) != 2 {
		t.Fatal("snapshot shared with the recorder")
	}
	// Nothing is recorded without a recorder, on a suppressed one, or on nil.
	RecorderFrom(context.Background()).Record(call("/x"))
	RecorderFrom(WithoutRecorder(ctx)).Record(call("/x"))
	if RecorderFrom(WithoutRecorder(ctx)) != nil || RecorderFrom(context.Background()) != nil {
		t.Fatal("RecorderFrom found a recorder where none should be")
	}
	var nilRec *Recorder
	nilRec.Record(Call{})
	nilRec.Add(ev, Cached)
	if nilRec.Evidence() != nil || len(rec.Evidence().Calls()) != 2 {
		t.Fatal("suppressed record leaked")
	}
	if WithoutRecorder(context.Background()) != context.Background() {
		t.Error("WithoutRecorder wrapped a context that had no recorder")
	}
	var nilEv *Evidence
	if nilEv.Calls() != nil || nilEv.Truncated() || nilEv.AsCached() != nil || Of() != nil {
		t.Error("nil evidence is not empty")
	}
}

// Calls a check got from a cache or a concurrent check's lookup are held by
// reference and marked by origin when flattened; the source is untouched.
func TestOrigins(t *testing.T) {
	src := Of(call("/a"), Call{Method: "GET", Path: "/c", Status: 200, Cached: true})
	rec := &Recorder{}
	rec.Add(nil, Cached)
	rec.Add(src, Cached)
	got := rec.Evidence().Calls()
	if len(got) != 2 || !got[0].Cached || got[0].Shared || !got[1].Cached {
		t.Fatalf("cached: %+v", got)
	}
	rec = &Recorder{}
	rec.Add(src, Shared)
	got = rec.Evidence().Calls()
	if len(got) != 2 || got[0].Cached || !got[0].Shared || !got[1].Cached || got[1].Shared {
		t.Fatalf("shared: %+v", got)
	}
	rec = &Recorder{}
	rec.Add(src, Own)
	rec.Record(call("/own"))
	got = rec.Evidence().Calls()
	if len(got) != 3 || got[0].Cached || got[0].Shared || !got[1].Cached || got[2].Path != "/own" {
		t.Fatalf("own: %+v", got)
	}
	if c := src.Calls(); c[0].Cached || c[0].Shared {
		t.Error("Add changed the source")
	}
	// Nesting: a decision served from the decision cache marks everything
	// cached, whatever it was before.
	cached := rec.Evidence().AsCached().Calls()
	for _, c := range cached {
		if !c.Cached || c.Shared {
			t.Fatalf("AsCached: %+v", cached)
		}
	}
	// A shared view of a cached view stays cached.
	rec2 := &Recorder{}
	rec2.Add(rec.Evidence().AsCached(), Shared)
	for _, c := range rec2.Evidence().Calls() {
		if !c.Cached || c.Shared {
			t.Fatalf("shared of cached: %+v", c)
		}
	}
}

func TestOldest(t *testing.T) {
	rec := &Recorder{}
	if _, ok := rec.Oldest(); ok {
		t.Fatal("empty recorder has an oldest read")
	}
	rec.Record(call("/own"))
	rec.Add(Of(call("/now")), Cached)
	if _, ok := rec.Oldest(); ok {
		t.Fatal("own and undated reads have no age")
	}
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rec.AddAt(Of(call("/a")), Cached, t1.Add(time.Hour))
	rec.AddAt(nil, Cached, t1)
	rec.AddAt(Of(call("/b")), Shared, t1.Add(2*time.Hour))
	if o, ok := rec.Oldest(); !ok || !o.Equal(t1) {
		t.Fatalf("oldest = %v %v", o, ok)
	}
	if n := len(rec.Evidence().Calls()); n != 4 {
		t.Fatalf("calls = %d", n)
	}
	// The cached view is one object, built once.
	ev := rec.Evidence()
	if ev.AsCached() != ev.AsCached() {
		t.Fatal("AsCached built two views")
	}
}

func TestCap(t *testing.T) {
	rec := &Recorder{}
	for i := 0; i < MaxCalls+5; i++ {
		rec.Record(call("/p"))
	}
	ev := rec.Evidence()
	if len(ev.Calls()) != MaxCalls || !ev.Truncated() {
		t.Fatalf("len=%d truncated=%v", len(ev.Calls()), ev.Truncated())
	}
	// Truncation carries over to whoever replays the evidence.
	rec2 := &Recorder{}
	rec2.Add(ev, Own)
	if !rec2.Evidence().Truncated() {
		t.Error("truncation not carried over")
	}
	// Replayed calls fill the cap first; the check's own calls then take
	// the place of the oldest replayed ones, never the other way round.
	replayed := &Recorder{}
	for i := 0; i < MaxCalls; i++ {
		replayed.Record(call("/replayed"))
	}
	rec = &Recorder{}
	rec.Add(replayed.Evidence(), Cached)
	rec.Record(call("/live-1"))
	rec.Record(call("/live-2"))
	rec.Add(Of(call("/replayed-late")), Cached)
	ev = rec.Evidence()
	got := ev.Calls()
	if len(got) != MaxCalls || !ev.Truncated() {
		t.Fatalf("len=%d truncated=%v", len(got), ev.Truncated())
	}
	// The own calls stay, in order, where they were among the replayed.
	var own []string
	for _, c := range got {
		if !c.Cached {
			own = append(own, c.Path)
		}
	}
	if strings.Join(own, ",") != "/live-1,/live-2" {
		t.Fatalf("live calls dropped: %v", own)
	}
	// It is the oldest replayed calls that went: the late one is kept.
	if got[MaxCalls-1].Path != "/replayed-late" || !got[MaxCalls-1].Cached {
		t.Fatalf("last call: %+v", got[MaxCalls-1])
	}
	// With nothing replayed left, the oldest own call goes: the last calls
	// a check made are the ones that decided it.
	rec = &Recorder{}
	for i := 0; i < MaxCalls; i++ {
		rec.Record(call("/page"))
	}
	rec.Record(Call{Method: "POST", Path: "/decides", Status: 200})
	got = rec.Evidence().Calls()
	if len(got) != MaxCalls || got[MaxCalls-1].Path != "/decides" || !rec.Evidence().Truncated() {
		t.Fatalf("deciding call dropped: %+v", got[MaxCalls-1])
	}
}

func TestJSON(t *testing.T) {
	rec := &Recorder{}
	rec.Add(Of(Call{Method: "GET", Path: "/users/u", Status: 200, ETag: `"v1"`}), Cached)
	rec.Record(Call{Method: "GET", Path: "/perm", Status: 200, SHA256: "ab"})
	b, err := json.Marshal(rec.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"upstream":[{"method":"GET","path":"/users/u","status":200,"etag":"\"v1\"","cached":true},{"method":"GET","path":"/perm","status":200,"sha256":"ab"}]}`
	if string(b) != want {
		t.Fatalf("\n got %s\nwant %s", b, want)
	}
	var back Evidence
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if c := back.Calls(); len(c) != 2 || !c[0].Cached || c[1].SHA256 != "ab" || back.Truncated() {
		t.Fatalf("%+v", c)
	}
	// A nil pointer marshals as null, which omitempty leaves out.
	var s struct {
		E *Evidence `json:"e,omitempty"`
	}
	if b, _ := json.Marshal(s); string(b) != "{}" {
		t.Fatalf("%s", b)
	}
	// Truncation is written.
	tr := &Recorder{}
	for i := 0; i <= MaxCalls; i++ {
		tr.Record(call("/p"))
	}
	if b, _ := json.Marshal(tr.Evidence()); !strings.HasSuffix(string(b), `],"truncated":true}`) {
		t.Fatalf("%s", b[len(b)-40:])
	}
}
