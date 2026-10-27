package decoder

import (
	"bytes"
	"strings"
	"testing"
)

func TestDumpProtobufGenericFields(t *testing.T) {
	// field 1 varint 1, field 2 "abc", field 3 { field 1 varint 150 },
	// field 4 fixed64, field 5 fixed32, field 6 group { field 1 varint 7 }.
	var b []byte
	b = append(b, 0x08, 0x01)
	b = append(b, 0x12, 0x03, 'a', 'b', 'c')
	nested := []byte{0x08, 0x96, 0x01}
	b = append(b, 0x1a, byte(len(nested)))
	b = append(b, nested...)
	b = append(b, 0x21, 1, 2, 3, 4, 5, 6, 7, 8)
	b = append(b, 0x2d, 0x0a, 0x0b, 0x0c, 0x0d)
	b = append(b, 0x33, 0x08, 0x07, 0x34)

	var out bytes.Buffer
	if err := DumpProtobuf(&out, b, ProtoOptions{Indent: 2}); err != nil {
		t.Fatalf("DumpProtobuf: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"    1: varint 1\n",
		`    2: string(3) "abc"`,
		"    3: message(3) {",
		"      1: varint 150",
		"    4: fixed64 0x0807060504030201",
		"    5: fixed32 0x0d0c0b0a",
		"    6: group {",
		"      1: varint 7",
		"    }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestDumpProtobufBinaryValueIsHex(t *testing.T) {
	// field 2 with one non-UTF-8 byte.
	var out bytes.Buffer
	if err := DumpProtobuf(&out, []byte{0x12, 0x01, 0xff}, ProtoOptions{}); err != nil {
		t.Fatalf("DumpProtobuf: %v", err)
	}
	if !strings.Contains(out.String(), "2: bytes(1) ff") {
		t.Fatalf("expected hex fallback, got:\n%s", out.String())
	}
}

func TestDumpProtobufMalformedReturnsError(t *testing.T) {
	var out bytes.Buffer
	err := DumpProtobuf(&out, []byte{0x08}, ProtoOptions{})
	if err == nil {
		t.Fatal("expected an error for a truncated varint")
	}
	if !strings.Contains(err.Error(), "varint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDumpProtobufDepthLimit(t *testing.T) {
	inner := []byte{0x08, 0x01}
	mid := append([]byte{0x0a, byte(len(inner))}, inner...)
	outer := append([]byte{0x0a, byte(len(mid))}, mid...)

	var out bytes.Buffer
	if err := DumpProtobuf(&out, outer, ProtoOptions{MaxDepth: 1}); err != nil {
		t.Fatalf("DumpProtobuf: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "1: message(4) {") {
		t.Fatalf("expected the first level to be parsed:\n%s", got)
	}
	if !strings.Contains(got, "1: bytes(2) 0801") {
		t.Fatalf("expected the second level to fall back to bytes:\n%s", got)
	}
}
