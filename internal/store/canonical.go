package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// CanonicalJSON marshals v and re-emits it in canonical form: object
// keys sorted bytewise, no insignificant whitespace, number literals
// preserved. The output is byte-stable for equal values, which the hash
// chain (section 9.3) and invariant I6 both require.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json: marshal: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON re-emits raw JSON bytes in canonical form. Numbers
// keep their source literal (decoded as json.Number), so canonicalizing
// twice is a fixed point.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical json: parse: %w", err)
	}
	// Reject trailing content after the first value.
	if dec.More() {
		return nil, errors.New("canonical json: trailing data after value")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical writes one decoded JSON value in canonical form.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case json.Number:
		buf.WriteString(t.String())
	case float64:
		// Only reachable when a caller hands a decoded tree that did
		// not use json.Number. Encode via encoding/json for the same
		// formatting rules as a direct marshal.
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("canonical json: number: %w", err)
		}
		buf.Write(b)
	case string:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("canonical json: string: %w", err)
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("canonical json: key: %w", err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}
