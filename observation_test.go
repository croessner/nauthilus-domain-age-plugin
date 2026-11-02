// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestObservationReplayAcrossWindows preserves both deduplication and saturated-window ownership.
func TestObservationReplayAcrossWindows(t *testing.T) {
	for _, saturated := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "saturated"}[saturated], func(t *testing.T) {
			server := miniredis.RunT(t)

			client := redis.NewClient(&redis.Options{Addr: server.Addr()})
			defer func() { _ = client.Close() }()

			if saturated {
				members := make([]redis.Z, 10000)
				for i := range members {
					members[i] = redis.Z{Score: 1, Member: i}
				}

				if err := client.ZAdd(t.Context(), "{domain}:hour:1", members...).Err(); err != nil {
					t.Fatal(err)
				}
			}

			for _, hour := range []string{"1", "2"} {
				keys := []string{"{domain}:first", "{domain}:hour:" + hour, "{domain}:dedup:identity"}
				if _, err := client.Eval(t.Context(), observeScript, keys, 3600, "identity").Result(); err != nil {
					t.Fatal(err)
				}
			}

			count, err := client.ZCard(t.Context(), "{domain}:hour:2").Result()
			if err != nil || count != 0 {
				t.Fatalf("replay counted in new window: %d %v", count, err)
			}

			first, err := client.Get(t.Context(), "{domain}:first").Int64()
			if err != nil || first != 3600 {
				t.Fatalf("first observation: %d %v", first, err)
			}
		})
	}
}

// redisHost supplies only the runtime service used by observation collection and effects.
type redisHost struct {
	api.Host
	service api.Redis
}

// Redis returns the real host facade over the isolated fixture database.
func (h redisHost) Redis() api.Redis { return h.service }

// TestAssessmentObservationLifecycle exercises real host scripts, typed requests and retry deduplication.
func TestAssessmentObservationLifecycle(t *testing.T) {
	server := miniredis.RunT(t)

	db := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer func() { _ = db.Close() }()

	host := redisHost{service: pluginruntime.NewRedisFacade(rediscli.NewTestClient(db))}

	p := &Plugin{config: configuration{Tracking: true, MaxAge: time.Hour}, data: &snapshot{GeneratedAt: time.Now(), byDomain: map[string]domainRecord{}}}
	if err := p.Start(t.Context(), host); err != nil {
		t.Fatal(err)
	}

	request, effect := observationRequests(t)

	result, err := (assessment{p}).Collect(t.Context(), request)
	if err != nil || factText(result, valueTrackingState) != valueUnknown {
		t.Fatalf("initial history: %v %v", result, err)
	}

	for range 2 {
		outcome, err := (observation{p}).Execute(t.Context(), effect)
		if err != nil || outcome.Outcome != api.DecisionEffectOutcomeSucceeded {
			t.Fatalf("record: %v %v", outcome, err)
		}
	}

	result, err = (assessment{p}).Collect(t.Context(), request)
	if err != nil || factText(result, valueTrackingState) != valueKnown {
		t.Fatalf("persisted history: %v %v", result, err)
	}

	for _, fact := range result.Facts {
		if fact.Name == valueObservations {
			count, _ := fact.Value.Integer()
			if count != 1 {
				t.Fatalf("replay count: %d", count)
			}
		}
	}
}

// stringFact constructs a typed caller-owned resource fixture without bypassing API validation.
func stringFact(t *testing.T, name, text string) api.DecisionFactView {
	t.Helper()

	value, err := api.NewDecisionValue(api.DecisionValueInput{String: &text})
	if err != nil {
		t.Fatal(err)
	}

	fact, err := api.NewDecisionFactView(api.DecisionFactViewInput{ID: name, Category: api.DecisionFactCategoryResource, Value: value})
	if err != nil {
		t.Fatal(err)
	}

	return fact
}

// factText reads one scalar result for lifecycle assertions.
func factText(result api.DecisionFactResult, name string) string {
	for _, fact := range result.Facts {
		if fact.Name == name {
			text, _ := fact.Value.StringValue()
			return text
		}
	}

	return ""
}

// observationRequests constructs matched immutable fact and effect requests for one message.
func observationRequests(t *testing.T) (api.DecisionFactRequest, api.DecisionEffectRequest) {
	t.Helper()

	target := api.DecisionTargetSelector{Namespace: namespaceMail, Action: valueObserveSenderDomain}

	caller, err := api.NewDecisionCallerView(api.DecisionCallerViewInput{Principal: "fixture", AuthenticationKind: "basic"})
	if err != nil {
		t.Fatal(err)
	}

	facts := []api.DecisionFactView{stringFact(t, valueResourceMailSenderDomain, "example.com"), stringFact(t, valueObservationID, "message-identity")}

	request, err := api.NewDecisionFactRequest(target, caller, facts)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := api.NewExecutionIdentityView("domain_age", "observation", "decision_effect", effectRecord, target)
	if err != nil {
		t.Fatal(err)
	}

	effect, err := api.NewDecisionEffectRequest(api.DecisionEffectRequestInput{Target: target, Caller: caller, Facts: facts, Effect: effectRecord, ExecutionIdentity: identity})
	if err != nil {
		t.Fatal(err)
	}

	return request, effect
}
