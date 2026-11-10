package main

import (
	"reflect"
	"testing"
)

func TestNormalizeArgs(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want []string
	}{
		{name: "server", argv: []string{"/usr/local/bin/hibp", "server", "--db", "x"}, want: []string{"server", "--db", "x"}},
		{name: "explicit helper", argv: []string{"/usr/local/bin/hibp", "helper", "facts"}, want: []string{"helper", "facts"}},
		{name: "helper name", argv: []string{"/usr/local/libexec/hibp/hibp-helper", "facts"}, want: []string{"helper", "facts"}},
		{name: "helper name check", argv: []string{"hibp-helper", "check"}, want: []string{"helper", "check"}},
		{name: "helper name explicit", argv: []string{"hibp-helper", "helper", "facts"}, want: []string{"helper", "facts"}},
		{name: "helper name no action", argv: []string{"hibp-helper"}, want: []string{"helper"}},
		{name: "helper name version", argv: []string{"hibp-helper", "version"}, want: []string{"version"}},
		{name: "preflight candidate version", argv: []string{"/usr/local/libexec/hibp/.hibp-helper.abc", "version"}, want: []string{"version"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeArgs(test.argv); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("normalizeArgs(%q) = %q, want %q", test.argv, got, test.want)
			}
		})
	}
}
