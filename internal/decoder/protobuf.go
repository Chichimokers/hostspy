// Package decoder turns the decrypted application byte stream of a proxied TCP
// connection into a chronological, human-readable sidecar. It understands the
// HTTP upgrade handshake, WebSocket framing (including fragmentation and
// control frames) and generic protobuf fields, but not any application schema:
// protobuf field numbers are printed without names.
//
// Decoding is best-effort. The raw per-connection log remains the source of
// truth, and decoding stops when the raw log cap truncates the stream.
package decoder

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ProtoOptions controls the generic protobuf field dump. It deliberately does
// not contain any Battle.net schema: field names are unknown, so only field
// numbers, wire types and values are printed.
type ProtoOptions struct {
	// MaxDepth is the maximum nesting depth. At the limit, length-delimited
	// values are printed as bytes instead of being parsed recursively.
	MaxDepth int
	// MaxStringBytes truncates very long printable strings. 0 uses a default.
	MaxStringBytes int
	// MaxHexBytes truncates very large binary values. 0 uses a default.
	MaxHexBytes int
	// Indent is the number of two-space levels to indent the first field.
	Indent int
}

func (o ProtoOptions) withDefaults() ProtoOptions {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 12
	}
	if o.MaxStringBytes <= 0 {
		o.MaxStringBytes = 8192
	}
	if o.MaxHexBytes <= 0 {
		o.MaxHexBytes = 64 << 10
	}
	if o.Indent < 0 {
		o.Indent = 0
	}
	return o
}

// DumpProtobuf writes a best-effort, schema-free dump of data as protobuf
// fields. It returns an error when the wire format is malformed. A malformed
// value is never silently presented as a valid message.
func DumpProtobuf(w io.Writer, data []byte, opts ProtoOptions) error {
	opts = opts.withDefaults()
	r := &pbReader{data: data}
	return dumpPBFields(w, r, 0, opts.Indent, opts)
}

type pbReader struct {
	data []byte
	off  int
}

func (r *pbReader) remaining() int { return len(r.data) - r.off }

func (r *pbReader) readVarint() (uint64, error) {
	var x uint64
	var s uint
	for i := 0; i < 10; i++ {
		if r.off >= len(r.data) {
			return 0, io.ErrUnexpectedEOF
		}
		b := r.data[r.off]
		r.off++
		if b < 0x80 {
			if i == 9 && b > 1 {
				return 0, fmt.Errorf("varint overflow at offset %d", r.off-1)
			}
			return x | uint64(b)<<s, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, fmt.Errorf("varint too long at offset %d", r.off)
}

func (r *pbReader) readKey() (int, int, error) {
	v, err := r.readVarint()
	if err != nil {
		return 0, 0, err
	}
	field := int(v >> 3)
	wire := int(v & 7)
	if field <= 0 || field > (1<<29)-1 {
		return 0, 0, fmt.Errorf("invalid field number %d at offset %d", field, r.off)
	}
	return field, wire, nil
}

func (r *pbReader) readBytes(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.data) {
		return nil, fmt.Errorf("need %d bytes at offset %d, have %d", n, r.off, r.remaining())
	}
	b := r.data[r.off : r.off+n]
	r.off += n
	return b, nil
}

func dumpPBFields(w io.Writer, r *pbReader, depth, indent int, opts ProtoOptions) error {
	pad := strings.Repeat("  ", indent)
	for r.off < len(r.data) {
		field, wire, err := r.readKey()
		if err != nil {
			return err
		}
		if wire == 4 {
			return fmt.Errorf("unexpected end-group for field %d at offset %d", field, r.off)
		}
		if err := dumpPBField(w, r, field, wire, depth, indent, pad, opts); err != nil {
			return err
		}
	}
	return nil
}

func dumpPBField(w io.Writer, r *pbReader, field, wire, depth, indent int, pad string, opts ProtoOptions) error {
	switch wire {
	case 0:
		v, err := r.readVarint()
		if err != nil {
			return fmt.Errorf("field %d varint: %w", field, err)
		}
		if v > uint64(1<<63-1) {
			fmt.Fprintf(w, "%s%d: varint %d (int64 %d)\n", pad, field, v, int64(v))
		} else {
			fmt.Fprintf(w, "%s%d: varint %d\n", pad, field, v)
		}
	case 1:
		b, err := r.readBytes(8)
		if err != nil {
			return fmt.Errorf("field %d fixed64: %w", field, err)
		}
		u := binary.LittleEndian.Uint64(b)
		fmt.Fprintf(w, "%s%d: fixed64 0x%016x (u=%d, i=%d)\n", pad, field, u, u, int64(u))
	case 5:
		b, err := r.readBytes(4)
		if err != nil {
			return fmt.Errorf("field %d fixed32: %w", field, err)
		}
		u := binary.LittleEndian.Uint32(b)
		fmt.Fprintf(w, "%s%d: fixed32 0x%08x (u=%d, i=%d)\n", pad, field, u, u, int32(u))
	case 2:
		l, err := r.readVarint()
		if err != nil {
			return fmt.Errorf("field %d length: %w", field, err)
		}
		if l > uint64(r.remaining()) {
			return fmt.Errorf("field %d length %d exceeds %d remaining bytes at offset %d", field, l, r.remaining(), r.off)
		}
		v, err := r.readBytes(int(l))
		if err != nil {
			return fmt.Errorf("field %d value: %w", field, err)
		}
		return dumpPBBytes(w, v, field, depth, indent, pad, opts)
	case 3:
		fmt.Fprintf(w, "%s%d: group {\n", pad, field)
		if depth >= opts.MaxDepth {
			if err := skipPBGroup(r, field); err != nil {
				return err
			}
			fmt.Fprintf(w, "%s}\n", pad)
			return nil
		}
		if err := dumpPBGroup(w, r, field, depth+1, indent+1, opts); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s}\n", pad)
	default:
		return fmt.Errorf("field %d: unsupported wire type %d at offset %d", field, wire, r.off)
	}
	return nil
}

func dumpPBGroup(w io.Writer, r *pbReader, groupField, depth, indent int, opts ProtoOptions) error {
	pad := strings.Repeat("  ", indent)
	for r.off < len(r.data) {
		field, wire, err := r.readKey()
		if err != nil {
			return err
		}
		if wire == 4 {
			if field != groupField {
				return fmt.Errorf("end-group for field %d, expected %d", field, groupField)
			}
			return nil
		}
		if err := dumpPBField(w, r, field, wire, depth, indent, pad, opts); err != nil {
			return err
		}
	}
	return io.ErrUnexpectedEOF
}

func skipPBGroup(r *pbReader, groupField int) error {
	for r.off < len(r.data) {
		field, wire, err := r.readKey()
		if err != nil {
			return err
		}
		if wire == 4 {
			if field != groupField {
				return fmt.Errorf("end-group for field %d, expected %d", field, groupField)
			}
			return nil
		}
		if err := skipPBField(r, field, wire); err != nil {
			return err
		}
	}
	return io.ErrUnexpectedEOF
}

func skipPBField(r *pbReader, field, wire int) error {
	switch wire {
	case 0:
		_, err := r.readVarint()
		return err
	case 1:
		_, err := r.readBytes(8)
		return err
	case 2:
		l, err := r.readVarint()
		if err != nil {
			return err
		}
		if l > uint64(r.remaining()) {
			return fmt.Errorf("field %d length %d exceeds %d remaining bytes", field, l, r.remaining())
		}
		_, err = r.readBytes(int(l))
		return err
	case 3:
		return skipPBGroup(r, field)
	case 5:
		_, err := r.readBytes(4)
		return err
	default:
		return fmt.Errorf("field %d: unsupported wire type %d", field, wire)
	}
}

func dumpPBBytes(w io.Writer, v []byte, field, depth, indent int, pad string, opts ProtoOptions) error {
	if len(v) == 0 {
		fmt.Fprintf(w, "%s%d: bytes(0) \"\"\n", pad, field)
		return nil
	}
	if printableUTF8(v) {
		fmt.Fprintf(w, "%s%d: string(%d) %s\n", pad, field, len(v), quoteBytes(v, opts.MaxStringBytes))
		return nil
	}
	if depth < opts.MaxDepth && validPbMessage(v) {
		fmt.Fprintf(w, "%s%d: message(%d) {\n", pad, field, len(v))
		r := &pbReader{data: v}
		if err := dumpPBFields(w, r, depth+1, indent+1, opts); err != nil {
			fmt.Fprintf(w, "%s  <parse error: %v>\n", pad, err)
			if opts.MaxHexBytes != 0 {
				writeHexIndent(w, v, strings.Repeat("  ", indent+1), opts.MaxHexBytes)
			}
		}
		fmt.Fprintf(w, "%s}\n", pad)
		return nil
	}
	fmt.Fprintf(w, "%s%d: bytes(%d) %s\n", pad, field, len(v), hexBytes(v, opts.MaxHexBytes))
	return nil
}

// validPbMessage reports whether the whole byte slice is a syntactically valid
// protobuf message. It is used as a conservative heuristic before recursing.
func validPbMessage(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	r := &pbReader{data: data}
	return validatePBFields(r, 0) == nil
}

func validatePBFields(r *pbReader, depth int) error {
	if depth > 32 {
		return fmt.Errorf("nesting too deep")
	}
	for r.off < len(r.data) {
		field, wire, err := r.readKey()
		if err != nil {
			return err
		}
		if err := validatePBField(r, field, wire, depth); err != nil {
			return err
		}
	}
	return nil
}

func validatePBField(r *pbReader, field, wire, depth int) error {
	switch wire {
	case 0:
		_, err := r.readVarint()
		return err
	case 1:
		_, err := r.readBytes(8)
		return err
	case 2:
		l, err := r.readVarint()
		if err != nil {
			return err
		}
		if l > uint64(r.remaining()) {
			return fmt.Errorf("field %d length %d exceeds %d remaining bytes", field, l, r.remaining())
		}
		_, err = r.readBytes(int(l))
		return err
	case 3:
		return validatePBGroup(r, field, depth+1)
	case 4:
		return fmt.Errorf("unexpected end-group for field %d", field)
	case 5:
		_, err := r.readBytes(4)
		return err
	default:
		return fmt.Errorf("field %d: unsupported wire type %d", field, wire)
	}
}

func validatePBGroup(r *pbReader, groupField, depth int) error {
	if depth > 32 {
		return fmt.Errorf("nesting too deep")
	}
	for r.off < len(r.data) {
		field, wire, err := r.readKey()
		if err != nil {
			return err
		}
		if wire == 4 {
			if field != groupField {
				return fmt.Errorf("end-group for field %d, expected %d", field, groupField)
			}
			return nil
		}
		if err := validatePBField(r, field, wire, depth); err != nil {
			return err
		}
	}
	return io.ErrUnexpectedEOF
}

func printableUTF8(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func quoteBytes(b []byte, max int) string {
	total := len(b)
	truncated := false
	if max > 0 && len(b) > max {
		b = truncateUTF8(b, max)
		truncated = true
	}
	s := strconv.Quote(string(b))
	if truncated {
		s += fmt.Sprintf(" ... (%d bytes total)", total)
	}
	return s
}

func truncateUTF8(b []byte, n int) []byte {
	if n <= 0 || n >= len(b) {
		return b
	}
	b = b[:n]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return b
}

func hexBytes(b []byte, max int) string {
	if max > 0 && len(b) > max {
		return hex.EncodeToString(b[:max]) + fmt.Sprintf(" ... (%d bytes total)", len(b))
	}
	return hex.EncodeToString(b)
}

func writeHexIndent(w io.Writer, b []byte, indent string, max int) {
	if len(b) == 0 {
		fmt.Fprintf(w, "%s(empty)\n", indent)
		return
	}
	limit := len(b)
	if max > 0 && limit > max {
		limit = max
	}
	for off := 0; off < limit; off += 16 {
		end := off + 16
		if end > limit {
			end = limit
		}
		fmt.Fprintf(w, "%s%08x  ", indent, off)
		for i := off; i < end; i++ {
			fmt.Fprintf(w, "%02x ", b[i])
		}
		fmt.Fprintln(w)
	}
	if limit < len(b) {
		fmt.Fprintf(w, "%s... (%d bytes omitted)\n", indent, len(b)-limit)
	}
}
