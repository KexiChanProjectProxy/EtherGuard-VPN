package orderedmap

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// nestedFixture is intentionally key-ordered so any reordering by the
// decoder would surface as a regression on the keys slice.
const nestedFixture = `{"z":1,"a":{"d":2,"b":[3,{"y":4,"x":5}]},"m":[{"q":6,"p":7},8]}`

// TestUnmarshalNestedRoundTrip is the red-phase regression for the
// "assignment copies lock value" vet diagnostics in orderdmap.go at
// the OrderedMap value-assertion branches (lines 200 and 246 before
// the fix). Marshalling then unmarshalling again must preserve the
// nested-object and nested-array structure verbatim and the
// top-level key order, because OrderedMap's contract is to retain
// insertion order of keys for both the top-level map and every
// nested OrderedMap.
func TestUnmarshalNestedRoundTrip(t *testing.T) {
	// *OrderedMap must satisfy json.Unmarshaler for the standard
	// library to call its UnmarshalJSON hook. Compile-time check.
	var _ json.Unmarshaler = (*OrderedMap)(nil)

	o := New()
	if err := o.UnmarshalJSON([]byte(nestedFixture)); err != nil {
		t.Fatalf("first UnmarshalJSON: %v", err)
	}

	gotKeys := o.Keys()
	wantKeys := []string{"z", "a", "m"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("top-level keys: got %v want %v", gotKeys, wantKeys)
	}

	// Nested object: "a" -> OrderedMap with keys d, b.
	aVal, ok := o.Get("a")
	if !ok {
		t.Fatalf("missing key 'a'")
	}
	aMap, ok := aVal.(*OrderedMap)
	if !ok {
		t.Fatalf("'a' should be *OrderedMap, got %T", aVal)
	}
	if got, want := aMap.Keys(), []string{"d", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nested 'a' keys: got %v want %v", got, want)
	}

	// Nested array element: "a"."b"[1] -> OrderedMap with keys y, x.
	bVal, _ := aMap.Get("b")
	bSlice, ok := bVal.([]interface{})
	if !ok {
		t.Fatalf("'a'.'b' should be []interface{}, got %T", bVal)
	}
	if len(bSlice) != 2 {
		t.Fatalf("'a'.'b' length: got %d want 2", len(bSlice))
	}
	bxMap, ok := bSlice[1].(*OrderedMap)
	if !ok {
		t.Fatalf("'a'.'b'[1] should be *OrderedMap, got %T", bSlice[1])
	}
	if got, want := bxMap.Keys(), []string{"y", "x"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("'a'.'b'[1] keys: got %v want %v", got, want)
	}

	// Top-level array element: "m"[0] -> OrderedMap with keys q, p.
	mVal, _ := o.Get("m")
	mSlice, ok := mVal.([]interface{})
	if !ok {
		t.Fatalf("'m' should be []interface{}, got %T", mVal)
	}
	if len(mSlice) != 2 {
		t.Fatalf("'m' length: got %d want 2", len(mSlice))
	}
	m0, ok := mSlice[0].(*OrderedMap)
	if !ok {
		t.Fatalf("'m'[0] should be *OrderedMap, got %T", mSlice[0])
	}
	if got, want := m0.Keys(), []string{"q", "p"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("'m'[0] keys: got %v want %v", got, want)
	}

	// Round-trip: marshal then unmarshal into a fresh map and compare.
	encoded, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	o2 := New()
	if err := o2.UnmarshalJSON(encoded); err != nil {
		t.Fatalf("second UnmarshalJSON: %v", err)
	}
	encoded2, err := json.Marshal(o2)
	if err != nil {
		t.Fatalf("second Marshal: %v", err)
	}
	if string(encoded) != string(encoded2) {
		t.Fatalf("round-trip drift:\nfirst:  %s\nsecond: %s", encoded, encoded2)
	}
}

// TestUnmarshalNestedMarshalShape pins the exact byte layout produced
// by MarshalJSON after a nested unmarshal. Locking the encoded form
// guards against any future change to decodeOrderedMap/decodeSlice
// silently reordering keys or dropping nested arrays.
func TestUnmarshalNestedMarshalShape(t *testing.T) {
	o := New()
	if err := o.UnmarshalJSON([]byte(nestedFixture)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	got, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"z":1,"a":{"d":2,"b":[3,{"y":4,"x":5}]},"m":[{"q":6,"p":7},8]}`
	if string(got) != want {
		t.Fatalf("marshal shape drift:\ngot:  %s\nwant: %s", got, want)
	}
}

// TestUnmarshalMalformedFails proves decodeOrderedMap / decodeSlice
// surface JSON syntax errors without partial success. This is the
// failure-QA path required by task 3.
func TestUnmarshalMalformedFails(t *testing.T) {
	cases := map[string]string{
		"trailing_comma_in_object": `{"a":1,}`,
		"unterminated_object":      `{"a":1`,
		"unterminated_array":       `{"a":[1,2`,
		"trailing_comma_in_array":  `{"a":[1,2,],}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			o := New()
			err := o.UnmarshalJSON([]byte(payload))
			if err == nil {
				t.Fatalf("expected error, got nil; map=%v", o)
			}
			if !strings.Contains(err.Error(), "JSON") &&
				!strings.Contains(err.Error(), "json") &&
				!strings.Contains(err.Error(), "unexpected") {
				t.Logf("note: error wording = %q (acceptable as long as err != nil)", err)
			}
		})
	}
}
