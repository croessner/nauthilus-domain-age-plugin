// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestBootstrapValidation admits complete secure routing snapshots and rejects ambiguous updates.
func TestBootstrapValidation(t *testing.T) {
	for _, test := range []struct {
		name, body string
		valid      bool
	}{
		{"secure", `{"services":[[["com","net"],["https://registry.example/rdap"]]]}`, true},
		{"empty", `{"services":[]}`, false},
		{"duplicate", `{"services":[[["com","com"],["https://registry.example"]]]}`, false},
		{"credentials", `{"services":[[["com"],["https://user:password@registry.example"]]]}`, false},
		{"insecure", `{"services":[[["com"],["http://registry.example"]]]}`, false},
		{"malformed", `{"services":[[["com"]]]}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeBootstrap([]byte(test.body))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}

// TestBootstrapRefreshRetainsLastGoodRoutes prevents failed refreshes from corrupting routing evidence.
func TestBootstrapRefreshRetainsLastGoodRoutes(t *testing.T) {
	c, err := newRDAPClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	fixture := &fixtureTransport{status: 200, body: `{"services":[[["com"],["https://registry.example/rdap"]]]}`}

	c.client.Transport = fixture
	if err := c.refreshBootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}

	acquired := c.bootstrapUpdatedAt
	if acquired.IsZero() || c.endpoints["com"] != "https://registry.example/rdap" {
		t.Fatal("valid routes not installed")
	}

	for _, body := range []string{`{}`, strings.Repeat("x", bootstrapMaxBytes+1)} {
		fixture.body = body

		if err := c.refreshBootstrap(t.Context()); err == nil {
			t.Fatal("invalid update accepted")
		}

		if c.bootstrapUpdatedAt != acquired || c.endpoints["com"] != "https://registry.example/rdap" {
			t.Fatal("last good routes changed")
		}
	}
}

// TestAutomaticBootstrapExpiryDisablesNetwork preserves local service availability on stale routing.
func TestAutomaticBootstrapExpiryDisablesNetwork(t *testing.T) {
	c, err := newRDAPClient(map[string]string{"com": "https://registry.example/rdap"})
	if err != nil {
		t.Fatal(err)
	}

	fixture := &fixtureTransport{}
	c.client.Transport = fixture

	c.automatic = true
	for _, test := range []struct {
		age   time.Duration
		state string
	}{
		{0, "bootstrap_unavailable"},
		{31 * 24 * time.Hour, "bootstrap_stale"},
	} {
		c.bootstrapUpdatedAt = time.Time{}
		if test.age != 0 {
			c.bootstrapUpdatedAt = time.Now().Add(-test.age)
		}

		if result := c.lookup(t.Context(), "example.com", time.Hour); result.state != test.state {
			t.Fatalf("state=%s want=%s", result.state, test.state)
		}
	}

	if fixture.calls != 0 {
		t.Fatal("lookup used invalid routing")
	}
}

// bootstrapHost runs one host-managed worker and exposes its lifecycle completion.
type bootstrapHost struct {
	api.Host
	done     chan struct{}
	lifetime context.Context
}

// ServiceContext supplies the parent context without exporting host internals.
func (bootstrapHost) ServiceContext() context.Context { return context.Background() }

// Logger disables fixture logging without changing worker control flow.
func (bootstrapHost) Logger(string) api.Logger { return nil }

// Go mirrors host ownership of one cancelable background task.
func (h bootstrapHost) Go(ctx context.Context, _ string, task func(context.Context) error) {
	worker, cancel := context.WithCancel(context.WithoutCancel(ctx))

	release := context.AfterFunc(h.lifetime, cancel)
	go func() { defer close(h.done); defer cancel(); defer release(); _ = task(worker) }()
}

// TestStopCancelsBootstrapWorker prevents a stopped plugin from retaining refresh goroutines.
func TestStopCancelsBootstrapWorker(t *testing.T) {
	for _, pluginStop := range []bool{true, false} {
		t.Run(map[bool]string{true: "plugin", false: "host"}[pluginStop], func(t *testing.T) {
			testBootstrapStop(t, pluginStop)
		})
	}
}

// testBootstrapStop checks independent plugin and host cancellation against detached caller semantics.
func testBootstrapStop(t *testing.T, pluginStop bool) {
	t.Helper()

	c, err := newRDAPClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	c.client.Transport = &fixtureTransport{status: 500}
	p := &Plugin{config: configuration{AutomaticRDAPBootstrap: true}, rdap: c}

	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()

	host := bootstrapHost{done: make(chan struct{}), lifetime: lifetime}
	if err := p.Start(t.Context(), host); err != nil {
		t.Fatal(err)
	}

	if pluginStop {
		if err := p.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
	} else {
		cancel()
	}

	select {
	case <-host.done:
	case <-time.After(time.Second):
		t.Fatal("bootstrap worker did not stop")
	}
}
