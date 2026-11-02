// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// rdapResult caches only bounded lookup facts with explicit expiry and provenance.
type rdapResult struct {
	registered time.Time
	checked    time.Time
	expires    time.Time
	state      string
}

// rdapClient serializes bounded registry traffic and owns a fixed-capacity cache.
type rdapClient struct {
	endpoints          map[string]string
	cache              map[string]rdapResult
	client             *http.Client
	next               time.Time
	bootstrapUpdatedAt time.Time
	mu                 sync.Mutex
	automatic          bool
}

// newRDAPClient accepts only operator-pinned HTTPS registry bases and never follows redirects.
func newRDAPClient(endpoints map[string]string) (*rdapClient, error) {
	if err := validateEndpoints(endpoints); err != nil {
		return nil, err
	}

	transport := &http.Transport{DialContext: publicDial, TLSHandshakeTimeout: time.Second, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	client := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	return &rdapClient{endpoints: endpoints, cache: make(map[string]rdapResult), client: client}, nil
}

// validateEndpoints admits only credential-free HTTPS registry routes.
func validateEndpoints(endpoints map[string]string) error {
	for tld, base := range endpoints {
		parsed, err := url.Parse(base)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(tld, "./:") {
			return errInput
		}
	}

	return nil
}

// publicDial pins each connection to a resolved public address, preventing DNS rebinding into local networks.
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		ip = ip.Unmap()
		if !publicIP(ip) {
			return nil, errInput
		}
	}

	for _, ip := range ips {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
	}

	return nil, errInput
}

// publicIP excludes private, special-use and documentation networks from registry connections.
func publicIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}

	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "64:ff9b::/96"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return false
		}
	}

	return true
}

// lookup returns cached data first and permits at most one outstanding registry request.
func (c *rdapClient) lookup(ctx context.Context, domain string, maxAge time.Duration) rdapResult {
	if !c.mu.TryLock() {
		return rdapResult{state: "busy"}
	}
	defer c.mu.Unlock()

	now := time.Now()
	if cached, ok := c.cache[domain]; ok && now.Before(cached.expires) && (cached.state != valueKnown || now.Sub(cached.checked) < maxAge) {
		return cached
	}

	if state := c.bootstrapState(now); state != "" {
		return rdapResult{state: state}
	}

	_, tld, _ := strings.Cut(domain, ".")
	// Public suffixes can contain multiple labels; choose the final TLD for RDAP bootstrap.
	labels := strings.Split(tld, ".")

	base := c.endpoints[labels[len(labels)-1]]
	if base == "" {
		return rdapResult{state: "unsupported"}
	}

	if now.Before(c.next) {
		return rdapResult{state: valueRateLimited}
	}

	c.next = now.Add(time.Second)

	result := c.fetch(ctx, strings.TrimRight(base, "/")+"/domain/"+url.PathEscape(domain), domain, now)
	if len(c.cache) >= 4096 {
		clear(c.cache)
	}

	c.cache[domain] = result

	return result
}

// bootstrapState checks automatic routing freshness while the caller holds the client lock.
func (c *rdapClient) bootstrapState(now time.Time) string {
	if !c.automatic {
		return ""
	}

	if c.bootstrapUpdatedAt.IsZero() {
		return "bootstrap_unavailable"
	}

	if now.Sub(c.bootstrapUpdatedAt) > bootstrapMaxAge {
		return stateBootstrapStale
	}

	return ""
}

// fetch validates status and a bounded body without allowing caller-controlled URLs.
func (c *rdapClient) fetch(ctx context.Context, target, domain string, now time.Time) rdapResult {
	result := rdapResult{state: valueUnavailable, expires: now.Add(time.Minute)}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result
	}

	request.Header.Set("Accept", "application/rdap+json")

	response, err := c.client.Do(request)
	if err != nil {
		return result
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusNotFound:
		result.state = "not_found"
		return result
	case http.StatusTooManyRequests:
		result.state = valueRateLimited
		c.next = now.Add(time.Minute)

		return result
	case http.StatusOK:
	default:
		return result
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return result
	}

	registered, err := decodeRDAP(body, domain, now)
	if err != nil {
		result.state = "missing_or_invalid_date"
		return result
	}

	return rdapResult{registered: registered, checked: now, expires: now.Add(24 * time.Hour), state: valueKnown}
}
