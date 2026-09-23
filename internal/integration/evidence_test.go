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
	RecordCall(ctx, Call{Method: "GET", Path: "/a", Status: 200, ETag: `"1"`})
	ev := rec.Evidence()
	if ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Path != "/a" || ev.Truncated {
		t.Fatalf("%+v", ev)
	}
	// The snapshot does not change under later records.
	RecordCall(ctx, Call{Method: "GET", Path: "/b", Status: 404})
	if len(ev.Upstream) != 1 || len(rec.Evidence().Upstream) != 2 {
		t.Fatal("snapshot shared with the recorder")
	}
	// Nothing is recorded without a recorder, on a suppressed one, or on nil.
	RecordCall(context.Background(), Call{Path: "/x"})
	RecordCall(WithoutRecorder(ctx), Call{Path: "/x"})
	var nilRec *Recorder
	nilRec.Record(Call{})
	nilRec.AddCached(ev)
	if nilRec.Evidence() != nil || len(rec.Evidence().Upstream) != 2 {
		t.Fatal("suppressed record leaked")
	}
	if WithoutRecorder(context.Background()) != context.Background() {
		t.Error("WithoutRecorder wrapped a context that had no recorder")
	}
	// Cached calls are marked; a nil evidence adds nothing.
	rec2 := &Recorder{}
	rec2.AddCached(nil)
	rec2.AddCached(ev)
	got := rec2.Evidence()
	if len(got.Upstream) != 1 || !got.Upstream[0].Cached || got.Upstream[0].Path != "/a" {
		t.Fatalf("%+v", got)
	}
	if ev.Upstream[0].Cached {
		t.Error("AddCached changed the source")
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
	rec2.AddCached(ev)
	if !rec2.Evidence().Truncated {
		t.Error("truncation not carried over")
	}
}
