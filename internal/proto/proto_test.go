package proto

import (
	"bytes"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Msg{Kind: KindRequest, ShareID: "demo", Target: "10.0.0.5:5432", Reason: "fix", Who: "emma"}
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestFramingLeavesRawBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMsg(&buf, Msg{Kind: KindDataHello, Role: "agent", ConnID: "abc"}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("RAW TUNNEL BYTES")

	if _, err := ReadMsg(&buf); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "RAW TUNNEL BYTES" {
		t.Fatalf("after one frame, remaining = %q", rest)
	}
}

func TestRejectsOversizeHeader(t *testing.T) {
	r := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadMsg(r); err == nil {
		t.Fatal("expected error on oversize frame header")
	}
}
