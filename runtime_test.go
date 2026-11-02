// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestDescriptorsAreAdmitted catches incompatible scalar bounds before host activation.
func TestDescriptorsAreAdmitted(t *testing.T) {
	if err := api.ValidateDecisionFactProviderDescriptor((assessment{}).Descriptor()); err != nil {
		t.Fatal(err)
	}

	if err := api.ValidateDecisionEffectProviderDescriptor((observation{}).Descriptor()); err != nil {
		t.Fatal(err)
	}
}

// testConfig supplies the narrow decoder used by reload tests.
type testConfig struct {
	api.ConfigView
	config configuration
}

// Decode returns an owned replacement configuration without a real host configuration loader.
func (v testConfig) Decode(target any) error { *target.(*configuration) = v.config; return nil }

// TestReloadPreservesLastGoodSnapshot exercises atomic replacement and rejection.
func TestReloadPreservesLastGoodSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.json")
	original := &snapshot{GeneratedAt: time.Now()}
	p := &Plugin{data: original, config: configuration{Database: path, MaxAge: time.Hour}}
	cfg := testConfig{config: p.config}

	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	if err := p.Reconfigure(t.Context(), cfg); err == nil || p.data != original {
		t.Fatal("invalid replacement changed live data")
	}

	writeSnapshotFixture(t, path)

	if err := p.Reconfigure(t.Context(), cfg); err != nil || p.data == original {
		t.Fatalf("replacement: %v", err)
	}
}

// fixtureTransport runs RDAP status and cache tests without networking.
type fixtureTransport struct {
	calls  int
	status int
	body   string
}

// RoundTrip supplies a bounded registry fixture while respecting cancellation.
func (f *fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}

	f.calls++

	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(f.body)), Header: make(http.Header)}, nil
}

// TestRDAPCacheAndFailureStates keeps 404 and rate-limit outcomes distinct from trustworthy age.
func TestRDAPCacheAndFailureStates(t *testing.T) {
	for _, status := range []int{200, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, err := newRDAPClient(map[string]string{"com": "https://registry.example/rdap"})
			if err != nil {
				t.Fatal(err)
			}

			transport := &fixtureTransport{status: status, body: `{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}`}
			c.client.Transport = transport
			first := c.lookup(context.Background(), "example.com", 24*time.Hour)

			second := c.lookup(context.Background(), "example.com", 24*time.Hour)
			if first.state != second.state || transport.calls != 1 {
				t.Fatal("cache did not retain explicit result")
			}

			if (first.state == valueKnown) != (status == 200) {
				t.Fatalf("status=%d result=%s", status, first.state)
			}
		})
	}
}

// TestRDAPCacheRespectsFreshness refreshes entries invalidated by a shorter live freshness limit.
func TestRDAPCacheRespectsFreshness(t *testing.T) {
	c, err := newRDAPClient(map[string]string{"com": "https://registry.example/rdap"})
	if err != nil {
		t.Fatal(err)
	}

	transport := &fixtureTransport{status: 200, body: `{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}`}
	c.client.Transport = transport

	c.cache["example.com"] = rdapResult{state: valueKnown, registered: time.Now().Add(-24 * time.Hour), checked: time.Now().Add(-2 * time.Hour), expires: time.Now().Add(time.Hour)}
	if result := c.lookup(t.Context(), "example.com", time.Hour); result.state != valueKnown || transport.calls != 1 {
		t.Fatalf("stale entry not refreshed: %s, calls=%d", result.state, transport.calls)
	}
}

// TestReloadRejectsInvalidBootstrap preserves a valid running configuration on malformed routing updates.
func TestReloadRejectsInvalidBootstrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	writeSnapshotFixture(t, path)
	cfg := configuration{Database: path, MaxAge: time.Hour, RDAP: map[string]string{"com": "https://registry.example/rdap"}, RDAPBootstrapUpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	p := &Plugin{config: cfg, data: &snapshot{}}
	replacement := cfg

	replacement.RDAPBootstrapUpdatedAt = "not-a-date"
	if err := p.Reconfigure(t.Context(), testConfig{config: replacement}); err == nil {
		t.Fatal("invalid bootstrap accepted")
	}

	if p.config.RDAPBootstrapUpdatedAt != cfg.RDAPBootstrapUpdatedAt {
		t.Fatal("live bootstrap mutated")
	}
}

// TestDescriptorIsDeterministic prevents generation metadata drift from map iteration order.
func TestDescriptorIsDeterministic(t *testing.T) {
	want := (assessment{}).Descriptor()
	for range 20 {
		if !reflect.DeepEqual(want, (assessment{}).Descriptor()) {
			t.Fatal("descriptor order changed")
		}
	}
}

// writeSnapshotFixture writes one valid empty snapshot for reload boundary tests.
func writeSnapshotFixture(t *testing.T, path string) {
	t.Helper()

	body := fmt.Sprintf(`{"generated_at":%q,"records":[]}`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestImporterPreservesDestination rejects bad inputs before replacing a maintained database.
func TestImporterPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	writeSnapshotFixture(t, output)

	original, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	if err = os.WriteFile(input, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	if err = importSnapshot(input, output); err == nil {
		t.Fatal("invalid snapshot installed")
	}

	current, err := os.ReadFile(output)
	if err != nil || string(current) != string(original) {
		t.Fatal("last good snapshot changed")
	}

	writeSnapshotFixture(t, input)

	if err = importSnapshot(input, output); err != nil {
		t.Fatal(err)
	}

	if _, err = loadSnapshot(output); err != nil {
		t.Fatal(err)
	}
}
