// Package diff reports field-level differences between two JSON documents.
package diff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

// Change is one differing field. Before is nil for an added field, After for a removed one.
type Change struct {
	Path   string
	Before any
	After  any
}

func (c Change) String() string {
	switch {
	case c.Before == nil:
		return fmt.Sprintf("+ %s: %s", c.Path, show(c.After))
	case c.After == nil:
		return fmt.Sprintf("- %s: %s", c.Path, show(c.Before))
	default:
		return fmt.Sprintf("~ %s: %s -> %s", c.Path, show(c.Before), show(c.After))
	}
}

// JSON compares two JSON documents and returns their changes sorted by path.
func JSON(before, after []byte) ([]Change, error) {
	var a, b any
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, fmt.Errorf("decode current document: %w", err)
	}
	if err := json.Unmarshal(after, &b); err != nil {
		return nil, fmt.Errorf("decode new document: %w", err)
	}
	var changes []Change
	walk("", a, b, &changes)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func walk(path string, a, b any, out *[]Change) {
	am, aIsMap := a.(map[string]any)
	bm, bIsMap := b.(map[string]any)
	if aIsMap && bIsMap {
		for key, av := range am {
			walk(join(path, key), av, bm[key], out)
		}
		for key, bv := range bm {
			if _, ok := am[key]; !ok {
				walk(join(path, key), nil, bv, out)
			}
		}
		return
	}
	as, aIsList := a.([]any)
	bs, bIsList := b.([]any)
	if aIsList && bIsList && len(as) == len(bs) {
		for i := range as {
			walk(path+"["+strconv.Itoa(i)+"]", as[i], bs[i], out)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, Change{Path: path, Before: a, After: b})
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func show(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(out)
}
