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
	"reflect"
	"runtime"
	"sort"
	"sync"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var buildCommit, buildTime, buildTags = valueUnknown, valueUnknown, "netgo"

// configuration owns operator inputs; endpoint maps are immutable after registration.
type configuration struct {
	CZDSDirectory          string            `mapstructure:"czds_directory"`
	RDAPBootstrapUpdatedAt string            `mapstructure:"rdap_bootstrap_updated_at"`
	Database               string            `mapstructure:"database"`
	RDAP                   map[string]string `mapstructure:"rdap"`
	MaxAgeText             string            `mapstructure:"max_age"`
	MaxAge                 time.Duration     `mapstructure:"-"`
	Tracking               bool              `mapstructure:"tracking"`
	AutomaticRDAPBootstrap bool              `mapstructure:"automatic_rdap_bootstrap"`
}

// Plugin coordinates immutable imports and optional bounded online enrichment.
type Plugin struct {
	czdsCancel      context.CancelFunc
	czds            *czdsStore
	bootstrapCancel context.CancelFunc
	data            *snapshot
	rdap            *rdapClient
	host            api.Host
	config          configuration
	mu              sync.RWMutex
}

// NauthilusPlugin exposes the native plugin factory.
func NauthilusPlugin() (api.Plugin, error) { return &Plugin{}, nil }

// Metadata declares a fact-only decision component and optional observation effect.
func (*Plugin) Metadata() api.Metadata {
	return api.Metadata{Name: "domain_age", Version: "0.1.3", APIVersion: api.APIVersion, Description: "Domain registration and independent first-seen intelligence", Features: []api.Feature{"decision_fact_provider", "decision_effect_provider", "reconfigure"}, Build: api.BuildInfo{ArtifactIdentity: api.NativeArtifactIdentity(), GoVersion: runtime.Version(), GitCommit: buildCommit, BuildTime: buildTime, BuildTags: []string{buildTags}}}
}

// Register validates all inputs before exposing a complete assessment component.
func (p *Plugin) Register(registrar api.Registrar) error {
	cfg, err := decodeConfiguration(registrar.Config())
	if err != nil {
		return err
	}

	data, err := loadSnapshot(cfg.Database)
	if err != nil {
		return err
	}

	if err := validateBootstrap(cfg); err != nil {
		return err
	}

	rdap, err := newRDAPClient(cfg.RDAP)
	if err != nil {
		return err
	}

	rdap.automatic = cfg.AutomaticRDAPBootstrap
	rdap.bootstrapUpdatedAt, _ = time.Parse(time.RFC3339, cfg.RDAPBootstrapUpdatedAt)

	decision, ok := registrar.(api.DecisionRegistrar)
	if !ok {
		return errInput
	}

	p.data, p.rdap, p.config = data, rdap, cfg
	if cfg.CZDSDirectory != "" {
		p.czds = &czdsStore{files: make(map[string]*czdsIndex), slots: make(chan struct{}, 4)}
	}

	if err = decision.RegisterDecisionFactProvider(assessment{p}); err != nil {
		return err
	}

	if cfg.Tracking {
		return decision.RegisterDecisionEffectProvider(observation{p})
	}

	return nil
}

// Start stores the host services only after optional observation script admission.
func (p *Plugin) Start(ctx context.Context, host api.Host) error {
	if host == nil {
		return errInput
	}

	if p.config.Tracking {
		if host.Redis() == nil || host.Redis().Scripts() == nil {
			return errInput
		}

		if _, err := host.Redis().Scripts().Upload(ctx, "domain_age_observe", observeScript); err != nil {
			return err
		}
	}

	p.mu.Lock()
	p.host = host
	p.mu.Unlock()

	if p.czds != nil {
		p.startCZDS(host)
	}

	if p.config.AutomaticRDAPBootstrap {
		p.startBootstrap(host)
	}

	return nil
}

// Stop releases pooled outbound connections after host request draining.
func (p *Plugin) Stop(context.Context) error {
	if p.czdsCancel != nil {
		p.czdsCancel()
	}

	if p.bootstrapCancel != nil {
		p.bootstrapCancel()
	}

	if p.rdap != nil {
		p.rdap.client.CloseIdleConnections()
	}

	return nil
}

// assessment reads current evidence without selecting delivery actions.
type assessment struct{ plugin *Plugin }

// outputKinds is the authoritative output vocabulary shared by registration and collection.
var outputKinds = map[string]api.DecisionValueKind{
	"observation_window_start_unix": api.DecisionValueKindInteger, "observation_window_seconds": api.DecisionValueKindInteger,
	valueDomain: api.DecisionValueKindString, valueRegistrationState: api.DecisionValueKindString, valueRegistrationSource: api.DecisionValueKindString,
	valueRegistrationAgeSeconds: api.DecisionValueKindInteger, valueExternalFirstSeenAgeSeconds: api.DecisionValueKindInteger,
	valueExternalFirstSeenState: api.DecisionValueKindString, valueExternalFirstSeenSource: api.DecisionValueKindString,
	valueDataAgeSeconds: api.DecisionValueKindInteger, valueDataStale: api.DecisionValueKindBoolean,
	valueRegistrationDataAgeSeconds: api.DecisionValueKindInteger, valueExternalDataAgeSeconds: api.DecisionValueKindInteger,
	valueTrackingState: api.DecisionValueKindString, valueLocalFirstSeenAgeSeconds: api.DecisionValueKindInteger, valueObservations: api.DecisionValueKindInteger,
}

// Descriptor binds a single typed caller-owned domain to a closed fact vocabulary.
func (assessment) Descriptor() api.DecisionFactProviderDescriptor {
	descriptor := api.DecisionFactProviderDescriptor{Name: "assessment", Namespace: namespaceMail, Timeout: 2 * time.Second, Targets: []api.DecisionTargetSelector{{Namespace: namespaceMail, Action: valueAssessSenderDomain}, {Namespace: namespaceMail, Action: valueObserveSenderDomain}}, Inputs: []api.DecisionFactInputDescriptor{{ID: valueResourceMailSenderDomain, Category: api.DecisionFactCategoryResource, Kind: api.DecisionValueKindString}}}

	for _, name := range sortedKeys(outputKinds) {
		kind := outputKinds[name]

		output := api.DecisionFactOutputDescriptor{Name: name, Kind: kind, Category: api.DecisionFactCategoryResource}
		if kind == api.DecisionValueKindString {
			output.MaxLength = 256
		}

		descriptor.Outputs = append(descriptor.Outputs, output)
	}

	return descriptor
}

// Collect emits independent evidence states; absent dates never become a known zero age.
func (a assessment) Collect(ctx context.Context, request api.DecisionFactRequest) (api.DecisionFactResult, error) {
	domain, err := domainFromFacts(request.Facts())
	if err != nil {
		return api.DecisionFactResult{ErrorClass: api.DecisionErrorClassInvalidInput}, nil
	}

	p := a.plugin
	p.mu.RLock()
	data, cfg := p.data, p.config
	p.mu.RUnlock()

	now := time.Now()
	age := int64(now.Sub(data.GeneratedAt).Seconds())
	stale := now.Sub(data.GeneratedAt) > cfg.MaxAge
	values := map[string]any{valueDomain: domain, valueDataAgeSeconds: age, valueDataStale: stale, valueRegistrationState: valueUnknown, valueExternalFirstSeenState: valueUnknown, valueTrackingState: "disabled"}

	record, found := data.byDomain[domain]
	mergeImport(values, record, found, now, cfg.MaxAge)
	p.mergeCZDS(ctx, values, domain, record, now, cfg.MaxAge)

	if (!found || record.RegisteredAt == nil || values[valueRegistrationState] == valueStale) && (len(cfg.RDAP) > 0 || cfg.AutomaticRDAPBootstrap) {
		result := rdapResult{state: stateBootstrapStale}
		if cfg.AutomaticRDAPBootstrap || bootstrapFresh(cfg) {
			result = p.rdap.lookup(ctx, domain, cfg.MaxAge)
		}

		values[valueRegistrationState] = result.state
		delete(values, valueRegistrationAgeSeconds)
		delete(values, valueRegistrationSource)

		if result.state == valueKnown {
			values[valueRegistrationSource] = "rdap"

			values[valueRegistrationDataAgeSeconds] = int64(now.Sub(result.checked).Seconds())
			if now.Sub(result.checked) > cfg.MaxAge {
				values[valueRegistrationState] = valueStale
			}

			values[valueRegistrationAgeSeconds] = int64(now.Sub(result.registered).Seconds())
		}
	}

	if cfg.Tracking {
		p.readObservations(ctx, domain, values, now)
	}

	return makeFacts(values)
}

// domainFromFacts validates one admitted domain fact without treating caller data as authentication.
func domainFromFacts(facts []api.DecisionFactView) (string, error) {
	for _, fact := range facts {
		if fact.ID() == valueResourceMailSenderDomain {
			value, ok := fact.Value().StringValue()
			if !ok {
				return "", errInput
			}

			return normalizeDomain(value)
		}
	}

	return "", errInput
}

// makeFacts converts the closed internal scalar vocabulary into strict plugin values.
func makeFacts(values map[string]any) (api.DecisionFactResult, error) {
	result := api.DecisionFactResult{}

	for _, name := range sortedKeys(values) {
		raw := values[name]
		input := api.DecisionValueInput{}

		switch value := raw.(type) {
		case string:
			input.String = &value
		case int64:
			input.Integer = &value
		case bool:
			input.Boolean = &value
		default:
			return result, errInput
		}

		value, err := api.NewDecisionValue(input)
		if err != nil {
			return api.DecisionFactResult{}, err
		}

		result.Facts = append(result.Facts, api.DecisionFactOutput{Name: name, Value: value})
	}

	return result, nil
}

// ValidateReconfigure verifies replacement snapshots without mutating the running generation.
func (p *Plugin) ValidateReconfigure(_ context.Context, input api.ConfigView) error {
	_, _, err := p.prepareReplacement(input)
	return err
}

// prepareReplacement keeps registration-time services fixed and validates the entire replacement.
func (p *Plugin) prepareReplacement(input api.ConfigView) (configuration, *snapshot, error) {
	cfg, err := decodeConfiguration(input)
	if err != nil {
		return cfg, nil, err
	}

	p.mu.RLock()
	old := p.config
	p.mu.RUnlock()

	if cfg.CZDSDirectory != old.CZDSDirectory || cfg.Tracking != old.Tracking || cfg.AutomaticRDAPBootstrap != old.AutomaticRDAPBootstrap || !reflect.DeepEqual(cfg.RDAP, old.RDAP) {
		return cfg, nil, fmt.Errorf("service configuration: %w", api.ErrRestartRequired)
	}

	if err := validateBootstrap(cfg); err != nil {
		return cfg, nil, err
	}

	data, err := loadSnapshot(cfg.Database)

	return cfg, data, err
}

// decodeConfiguration parses duration text explicitly because the host decoder has no duration hook.
func decodeConfiguration(input api.ConfigView) (configuration, error) {
	cfg := configuration{MaxAge: 48 * time.Hour}
	if err := input.Decode(&cfg); err != nil {
		return cfg, err
	}

	if cfg.MaxAgeText != "" {
		value, err := time.ParseDuration(cfg.MaxAgeText)
		if err != nil {
			return cfg, fmt.Errorf("max_age: %w", err)
		}

		cfg.MaxAge = value
	}

	if cfg.MaxAge < time.Minute || cfg.MaxAge > 30*24*time.Hour {
		return cfg, errInput
	}

	return cfg, nil
}

// Reconfigure atomically publishes validated imports, preserving the previous snapshot on failure.
func (p *Plugin) Reconfigure(_ context.Context, input api.ConfigView) error {
	cfg, data, err := p.prepareReplacement(input)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.config, p.data = cfg, data
	p.mu.Unlock()

	return nil
}

// mergeImport exposes independent imported evidence and its source freshness.
func mergeImport(values map[string]any, record domainRecord, found bool, now time.Time, maxAge time.Duration) {
	if found {
		if record.RegisteredAt != nil {
			values[valueRegistrationState] = valueKnown

			values[valueRegistrationDataAgeSeconds] = int64(now.Sub(*record.RegisteredCheckedAt).Seconds())
			if now.Sub(*record.RegisteredCheckedAt) > maxAge {
				values[valueRegistrationState] = valueStale
			}

			values[valueRegistrationSource] = record.RegisteredSource
			values[valueRegistrationAgeSeconds] = int64(now.Sub(*record.RegisteredAt).Seconds())
		}

		if record.FirstSeen != nil {
			values[valueExternalFirstSeenState] = valueKnown

			values[valueExternalDataAgeSeconds] = int64(now.Sub(*record.FirstSeenCheckedAt).Seconds())
			if now.Sub(*record.FirstSeenCheckedAt) > maxAge {
				values[valueExternalFirstSeenState] = valueStale
			}

			values[valueExternalFirstSeenSource] = record.FirstSeenSource
			values[valueExternalFirstSeenAgeSeconds] = int64(now.Sub(*record.FirstSeen).Seconds())
		}
	}
}

// validateBootstrap rejects malformed routing metadata without blocking startup for expired data.
func validateBootstrap(cfg configuration) error {
	if len(cfg.RDAP) == 0 {
		return nil
	}

	updated, err := time.Parse(time.RFC3339, cfg.RDAPBootstrapUpdatedAt)
	if err != nil || updated.After(time.Now()) {
		return errInput
	}

	return nil
}

// bootstrapFresh disables static online routing once its acquisition age exceeds thirty days.
func bootstrapFresh(cfg configuration) bool {
	updated, err := time.Parse(time.RFC3339, cfg.RDAPBootstrapUpdatedAt)
	return err == nil && !updated.After(time.Now()) && time.Since(updated) <= bootstrapMaxAge
}

// sortedKeys makes native descriptors and emitted fact order independent of map iteration.
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
