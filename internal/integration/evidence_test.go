package integration

import (
	"context"
	"testing"
)

func TestRecorder(t *testing.T) {
	ctx, rec := WithRecorder(context.Background())
	if rec.Evidence() != nil {
		t.Fatal("empty recorder has evidence")
	}
	RecorderFrom(ctx).Record(Call{Method: "GET", Path: "/a", Status: 200, ETag: `"1"`})
	ev := rec.Evidence()
	if ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Path != "/a" || ev.Truncated {
		t.Fatalf("%+v", ev)
	}
	// The snapshot does not change under later records.
	RecorderFrom(ctx).Record(Call{Method: "GET", Path: "/b", Status: 404})
	if len(ev.Upstream) != 1 || len(rec.Evidence().Upstream) != 2 {
		t.Fatal("snapshot shared with the recorder")
	}
	// Nothing is recorded without a recorder, on a suppressed one, or on nil.
	RecorderFrom(context.Background()).Record(Call{Path: "/x"})
	RecorderFrom(WithoutRecorder(ctx)).Record(Call{Path: "/x"})
	if RecorderFrom(WithoutRecorder(ctx)) != nil || RecorderFrom(context.Background()) != nil {
		t.Fatal("RecorderFrom found a recorder where none should be")
	}
	var nilRec *Recorder
	nilRec.Record(Call{})
	nilRec.Add(ev, Cached)
	if nilRec.Evidence() != nil || len(rec.Evidence().Upstream) != 2 {
		t.Fatal("suppressed record leaked")
	}
	if WithoutRecorder(context.Background()) != context.Background() {
		t.Error("WithoutRecorder wrapped a context that had no recorder")
	}
	// Cached calls are marked; a nil evidence adds nothing.
	rec2 := &Recorder{}
	rec2.Add(nil, Cached)
	rec2.Add(ev, Cached)
	got := rec2.Evidence()
	if len(got.Upstream) != 1 || !got.Upstream[0].Cached || got.Upstream[0].Path != "/a" {
		t.Fatalf("%+v", got)
	}
	if ev.Upstream[0].Cached {
		t.Error("Add changed the source")
	}
	// Own calls keep their flags; a cached call stays cached whatever the
	// origin; a shared one is shared unless cached.
	rec3 := &Recorder{}
	rec3.Add(got, Own)
	rec3.Add(ev, Own)
	rec3.Add(got, Shared)
	rec3.Add(ev, Shared)
	if c := rec3.Evidence().Upstream; !c[0].Cached || c[1].Cached || c[1].Shared || !c[2].Cached || c[2].Shared || c[3].Cached || !c[3].Shared {
		t.Fatalf("%+v", c)
	}
}

func TestRecorderCap(t *testing.T) {
	rec := &Recorder{}
	for i := 0; i < MaxEvidenceCalls+5; i++ {
		rec.Record(Call{Method: "GET", Path: "/p", Status: 200})
	}
	ev := rec.Evidence()
	if len(ev.Upstream) != MaxEvidenceCalls || !ev.Truncated {
		t.Fatalf("len=%d truncated=%v", len(ev.Upstream), ev.Truncated)
	}
	// Replayed calls fill the cap first; the check's own calls then take
	// the place of the oldest replayed ones, never the other way round.
	rec = &Recorder{}
	for i := 0; i < MaxEvidenceCalls; i++ {
		rec.Record(Call{Method: "GET", Path: "/replayed", Status: 200, Cached: true})
	}
	rec.Record(Call{Method: "GET", Path: "/live-1", Status: 200})
	rec.Record(Call{Method: "GET", Path: "/live-2", Status: 200})
	rec.Record(Call{Method: "GET", Path: "/replayed-late", Status: 200, Cached: true})
	ev = rec.Evidence()
	if len(ev.Upstream) != MaxEvidenceCalls || !ev.Truncated {
		t.Fatalf("len=%d truncated=%v", len(ev.Upstream), ev.Truncated)
	}
	if got := ev.Upstream[MaxEvidenceCalls-2:]; got[0].Path != "/live-1" || got[1].Path != "/live-2" {
		t.Fatalf("live calls dropped: %+v", got)
	}
	for _, c := range ev.Upstream {
		if c.Path == "/replayed-late" {
			t.Fatal("a replayed call displaced a live one")
		}
	}
	// With nothing replayed left, the oldest live call goes: the last
	// calls a check made are the ones that decided it.
	rec = &Recorder{}
	for i := 0; i < MaxEvidenceCalls; i++ {
		rec.Record(Call{Method: "GET", Path: "/page", Status: 200})
	}
	rec.Record(Call{Method: "POST", Path: "/decides", Status: 200})
	ev = rec.Evidence()
	if len(ev.Upstream) != MaxEvidenceCalls || ev.Upstream[MaxEvidenceCalls-1].Path != "/decides" || !ev.Truncated {
		t.Fatalf("deciding call dropped: %+v", ev.Upstream[MaxEvidenceCalls-1])
	}
	rec2 := &Recorder{}
	rec2.Add(ev, Own)
	if !rec2.Evidence().Truncated {
		t.Error("truncation not carried over")
	}
}
