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
	nilRec.Add(ev, true)
	if nilRec.Evidence() != nil || len(rec.Evidence().Upstream) != 2 {
		t.Fatal("suppressed record leaked")
	}
	if WithoutRecorder(context.Background()) != context.Background() {
		t.Error("WithoutRecorder wrapped a context that had no recorder")
	}
	// Cached calls are marked; a nil evidence adds nothing.
	rec2 := &Recorder{}
	rec2.Add(nil, true)
	rec2.Add(ev, true)
	got := rec2.Evidence()
	if len(got.Upstream) != 1 || !got.Upstream[0].Cached || got.Upstream[0].Path != "/a" {
		t.Fatalf("%+v", got)
	}
	if ev.Upstream[0].Cached {
		t.Error("Add changed the source")
	}
	// Live calls keep their flag; an already-cached call stays cached.
	rec3 := &Recorder{}
	rec3.Add(got, false)
	rec3.Add(ev, false)
	if c := rec3.Evidence().Upstream; !c[0].Cached || c[1].Cached {
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
	rec2 := &Recorder{}
	rec2.Add(ev, false)
	if !rec2.Evidence().Truncated {
		t.Error("truncation not carried over")
	}
}
