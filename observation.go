// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/redis/go-redis/v9"
)

// observeScript atomically records first observation and a bounded deduplicated hourly sample.
const observeScript = `
if redis.call('EXISTS', KEYS[3]) == 1 then return 1 end
local first = redis.call('GET', KEYS[1])
if not first then redis.call('SET', KEYS[1], ARGV[1], 'EX', 31536000) end
redis.call('SET', KEYS[3], '1', 'EX', 86400)
if redis.call('ZCARD', KEYS[2]) >= 10000 then return 0 end
redis.call('ZADD', KEYS[2], 'NX', ARGV[1], ARGV[2])
redis.call('EXPIRE', KEYS[2], 7200)
return 1
`

// observation is policy-selected and does not run during fact collection.
type observation struct{ plugin *Plugin }

// Descriptor requires an admitted idempotency identity and synchronous host execution.
func (observation) Descriptor() api.DecisionEffectProviderDescriptor {
	return api.DecisionEffectProviderDescriptor{Name: "observation", Namespace: namespaceMail, Effects: []api.DecisionEffectDescriptor{{Name: effectRecord, Execution: api.DecisionEffectExecutionHostSync, ReplaySafety: api.DecisionEffectReplayIdempotent, IdempotencyKey: valueObservationID, Targets: []api.DecisionTargetSelector{{Namespace: namespaceMail, Action: valueObserveSenderDomain}}}}}
}

// observationKeys separates persistent first-seen from UTC hourly counts in one Redis Cluster slot.
func observationKeys(host api.Host, domain string, now time.Time) []string {
	prefix := domainKeyPrefix(domain)

	return host.Redis().Keys().Keys(prefix+":first", prefix+":hour:"+strconv.FormatInt(now.Unix()/3600, 10))
}

// Execute records only an explicitly admitted observation, with no recipient or stage inflation.
func (o observation) Execute(ctx context.Context, request api.DecisionEffectRequest) (api.DecisionEffectResult, error) {
	failure := api.DecisionEffectResult{Outcome: api.DecisionEffectOutcomeFailed, ErrorClass: api.DecisionErrorClassInvalidInput}

	domain, err := domainFromFacts(request.Facts())
	if err != nil || request.Effect() != effectRecord {
		return failure, nil
	}

	identity := ""

	for _, fact := range request.Facts() {
		if fact.ID() == valueObservationID {
			identity, _ = fact.Value().StringValue()
		}
	}

	if identity == "" || len(identity) > 128 {
		return failure, nil
	}

	p := o.plugin
	p.mu.RLock()
	host := p.host
	p.mu.RUnlock()

	if host == nil {
		failure.ErrorClass = api.DecisionErrorClassUnavailable
		return failure, nil
	}

	now := time.Now()
	digest := sha256.Sum256([]byte(identity))

	_, err = host.Redis().Scripts().Run(ctx, "domain_age_observe", append(observationKeys(host, domain, now), host.Redis().Keys().Key(domainKeyPrefix(domain)+fmt.Sprintf(":seen:%x", digest))), now.Unix(), fmt.Sprintf("%x", digest))
	if err != nil {
		return api.DecisionEffectResult{Outcome: api.DecisionEffectOutcomeUnknown, ErrorClass: api.DecisionErrorClassUnavailable}, nil
	}

	return api.DecisionEffectResult{Outcome: api.DecisionEffectOutcomeSucceeded}, nil
}

// readObservations preserves storage failures as unavailable rather than a known zero count.
func (p *Plugin) readObservations(ctx context.Context, domain string, values map[string]any, now time.Time) {
	values[valueTrackingState] = valueUnavailable

	p.mu.RLock()
	host := p.host
	p.mu.RUnlock()

	if host == nil {
		return
	}

	keys := observationKeys(host, domain, now)

	first, err := host.Redis().Read().Get(ctx, keys[0]).Int64()
	if errors.Is(err, redis.Nil) {
		values[valueTrackingState] = valueUnknown
		return
	}

	if err != nil {
		return
	}

	count, err := host.Redis().Read().ZCard(ctx, keys[1]).Result()
	if err != nil || first > now.Unix() {
		return
	}

	values[valueTrackingState] = valueKnown
	values[valueLocalFirstSeenAgeSeconds] = now.Unix() - first

	values[valueObservations] = count
	values["observation_window_start_unix"] = (now.Unix() / 3600) * 3600

	values["observation_window_seconds"] = int64(3600)
	if count >= 10000 {
		values[valueTrackingState] = "saturated"
	}
}

// domainKeyPrefix centralizes the cluster-slot binding for all observation keys.
func domainKeyPrefix(domain string) string {
	return fmt.Sprintf("domain_age:{%x}", sha256.Sum256([]byte(domain)))
}
