// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"strings"
	"testing"
	"time"
)

// TestNormalizeDomain rejects ambiguous identities and preserves registrable IDNs.
func TestNormalizeDomain(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"MAIL.Example.COM.", "example.com"}, {"tößt.de", "xn--tt-gia5g.de"}, {"co.uk", ""}, {"127.0.0.1", ""}, {"foo@bar.com", ""}, {"a..com", ""}} {
		got, err := normalizeDomain(tc.input)
		if tc.want == "" {
			if err == nil {
				t.Errorf("accepted %q", tc.input)
			}

			continue
		}

		if err != nil || got != tc.want {
			t.Errorf("%q = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}

// TestSnapshotValidation prevents partial publication of malformed or duplicate records.
func TestSnapshotValidation(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		data  string
		valid bool
	}{
		{`{"generated_at":"2026-11-02T11:00:00Z","records":[{"domain":"example.com","registered_source":"fixture","registered_checked_at":"2026-11-02T10:00:00Z","registered_at":"2020-01-01T00:00:00Z"}]}`, true},
		{`{"generated_at":"2027-01-01T00:00:00Z","records":[]}`, false},
		{`{"generated_at":"2026-11-02T11:00:00Z","records":[{"domain":"example.com","registered_source":"fixture","registered_checked_at":"2026-11-02T10:00:00Z"},{"domain":"EXAMPLE.COM","registered_source":"fixture","registered_checked_at":"2026-11-02T10:00:00Z"}]}`, false},
		{`{"generated_at":"2026-11-02T11:00:00Z","unknown":true,"records":[]}`, false},
	} {
		_, err := decodeSnapshot(strings.NewReader(tc.data), now)
		if (err == nil) != tc.valid {
			t.Errorf("valid=%v error=%v", tc.valid, err)
		}
	}
}

// TestRDAPIdentity rejects unrelated and future registration records.
func TestRDAPIdentity(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}`, true},
		{`{"objectClassName":"domain","ldhName":"other.com","events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}`, false},
		{`{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]}`, false},
	} {
		_, err := decodeRDAP([]byte(tc.body), "example.com", now)
		if (err == nil) != tc.valid {
			t.Errorf("valid=%v err=%v", tc.valid, err)
		}
	}
}
