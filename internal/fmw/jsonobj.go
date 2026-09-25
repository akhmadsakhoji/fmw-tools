// Copyright (C) 2026 PT Founder Media Partner
// SPDX-License-Identifier: GPL-2.0-or-later

package fmw

import (
	"bytes"
	"encoding/json"
	"errors"
)

// object is a JSON object that keeps its key order and every value as
// written, so a rewritten manifest differs from the original only where it
// was changed, and keys this version does not know are kept.
type object []field

type field struct {
	Key string
	Val json.RawMessage
}

func parseObject(data []byte) (object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var o object
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		o = append(o, field{Key: key, Val: val})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return o, nil
}

func (o object) get(key string) (json.RawMessage, bool) {
	for _, f := range o {
		if f.Key == key {
			return f.Val, true
		}
	}
	return nil, false
}

// set replaces a value, or appends the key.
func (o *object) set(key string, v any) error {
	raw, err := marshal(v)
	if err != nil {
		return err
	}
	for i, f := range *o {
		if f.Key == key {
			(*o)[i].Val = raw
			return nil
		}
	}
	*o = append(*o, field{Key: key, Val: raw})
	return nil
}

func (o *object) del(keys ...string) {
	out := (*o)[:0]
	for _, f := range *o {
		drop := false
		for _, k := range keys {
			if f.Key == k {
				drop = true
			}
		}
		if !drop {
			out = append(out, f)
		}
	}
	*o = out
}

// MarshalJSON writes the fields in order.
func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := marshal(f.Key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.Val)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshal encodes without HTML escaping (like the plugin's JSON).
func marshal(v any) ([]byte, error) {
	if raw, ok := v.(json.RawMessage); ok {
		return raw, nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
