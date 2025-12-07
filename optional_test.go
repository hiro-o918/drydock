package drydock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestIsZero(t *testing.T) {
	type MyStruct struct {
		Field string
	}

	tests := []struct {
		name string
		val  any
		want bool
	}{
		// String cases
		{name: "String empty", val: "", want: true},
		{name: "String non-empty", val: "hello", want: false},
		// Int cases
		{name: "Int zero", val: 0, want: true},
		{name: "Int non-zero", val: 42, want: false},
		// Bool cases
		{name: "Bool false (zero)", val: false, want: true},
		{name: "Bool true", val: true, want: false},
		// Struct cases
		{name: "Struct empty", val: MyStruct{}, want: true},
		{name: "Struct populated", val: MyStruct{Field: "A"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// type switch or direct assertion logic isn't clean with table-driven generics
			// so we invoke the function based on the type in the test runner.
			var got bool

			switch v := tt.val.(type) {
			case string:
				got = drydock.IsZero(v)
			case int:
				got = drydock.IsZero(v)
			case bool:
				got = drydock.IsZero(v)
			case MyStruct:
				got = drydock.IsZero(v)
			default:
				t.Fatalf("unhandled type: %T", v)
			}

			if got != tt.want {
				t.Errorf("IsZero(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestToPtr(t *testing.T) {
	type MyStruct struct {
		ID int
	}

	// Helper to reduce boilerplate in test table
	sPtr := func(s string) *string { return &s }
	iPtr := func(i int) *int { return &i }
	stPtr := func(s MyStruct) *MyStruct { return &s }

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "String: empty returns nil",
			run: func(t *testing.T) {
				got := drydock.ToPtr("")
				if diff := cmp.Diff((*string)(nil), got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "String: value returns ptr",
			run: func(t *testing.T) {
				got := drydock.ToPtr("foo")
				want := sPtr("foo")
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "Int: zero returns nil",
			run: func(t *testing.T) {
				got := drydock.ToPtr(0)
				if diff := cmp.Diff((*int)(nil), got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "Int: value returns ptr",
			run: func(t *testing.T) {
				got := drydock.ToPtr(123)
				want := iPtr(123)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "Struct: empty returns nil",
			run: func(t *testing.T) {
				got := drydock.ToPtr(MyStruct{})
				if diff := cmp.Diff((*MyStruct)(nil), got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "Struct: value returns ptr",
			run: func(t *testing.T) {
				val := MyStruct{ID: 1}
				got := drydock.ToPtr(val)
				want := stPtr(val)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}
