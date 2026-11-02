// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	ianaBootstrapURL         = "https://data.iana.org/rdap/dns.json"
	bootstrapMaxAge          = 30 * 24 * time.Hour
	bootstrapRefreshInterval = 24 * time.Hour
	bootstrapRetryInterval   = 15 * time.Minute
	bootstrapMaxBytes        = 1 << 20
	bootstrapMaxDomains      = 4096
)

// startBootstrap binds one bounded refresh worker to the plugin lifecycle.
func (p *Plugin) startBootstrap(host api.Host) {
	parent := host.ServiceContext()
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	p.bootstrapCancel = cancel

	host.Go(ctx, "domain_age_rdap_bootstrap", func(hostCtx context.Context) error {
		// Host.Go detaches caller cancellation; bridge its lifetime into the plugin-owned context.
		release := context.AfterFunc(hostCtx, cancel)
		defer release()

		return p.rdap.runBootstrap(ctx, host.Logger("domain_age"))
	})
}

// runBootstrap refreshes independently of mail requests and retries failures with bounded frequency.
func (c *rdapClient) runBootstrap(ctx context.Context, logger api.Logger) error {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			delay := bootstrapRefreshInterval
			if err := c.refreshBootstrap(ctx); err != nil {
				delay = bootstrapRetryInterval

				if logger != nil && ctx.Err() == nil {
					logger.Warn(ctx, "RDAP bootstrap refresh failed; retaining last valid routes", api.LogField{Key: "error", Value: err.Error()})
				}
			}

			timer.Reset(delay)
		}
	}
}

// refreshBootstrap admits a complete official IANA snapshot before atomically replacing routes.
func (c *rdapClient) refreshBootstrap(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaBootstrapURL, nil)
	if err != nil {
		return err
	}

	response, err := c.client.Do(request)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("IANA bootstrap HTTP status %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, bootstrapMaxBytes+1))
	if err != nil || len(data) > bootstrapMaxBytes {
		return errInput
	}

	routes, err := decodeBootstrap(data)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.endpoints = routes
	c.bootstrapUpdatedAt = time.Now()
	c.mu.Unlock()

	return nil
}

// decodeBootstrap rejects malformed, duplicate or unsafe routing data without publishing partial maps.
func decodeBootstrap(data []byte) (map[string]string, error) {
	var document struct {
		Services [][][]string `json:"services"`
	}
	if json.Unmarshal(data, &document) != nil || len(document.Services) == 0 || len(document.Services) > bootstrapMaxDomains {
		return nil, errInput
	}

	routes := make(map[string]string)
	for _, service := range document.Services {
		if err := addBootstrapService(routes, service); err != nil {
			return nil, err
		}
	}

	if len(routes) == 0 || len(routes) > bootstrapMaxDomains {
		return nil, errInput
	}

	return routes, validateEndpoints(routes)
}

// addBootstrapService selects the first secure registry route and enforces unique canonical TLDs.
func addBootstrapService(routes map[string]string, service [][]string) error {
	if len(service) != 2 || len(service[0]) == 0 || len(service[1]) == 0 || len(service[1]) > 16 {
		return errInput
	}

	base := firstHTTPSRoute(service[1])
	if base == "" {
		return nil
	}

	for _, domain := range service[0] {
		if !validLabel(domain) || strings.ToLower(domain) != domain || len(routes) >= bootstrapMaxDomains {
			return errInput
		}

		if _, exists := routes[domain]; exists {
			return errInput
		}

		routes[domain] = base
	}

	return nil
}

// firstHTTPSRoute omits registries that publish no secure bootstrap endpoint.
func firstHTTPSRoute(candidates []string) string {
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, "https://") {
			return candidate
		}
	}

	return ""
}
