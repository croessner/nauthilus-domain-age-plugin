// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
)

// TestReferencePolicyNormalizes validates caller admission, schemas, schedules and rule vocabulary.
func TestReferencePolicyNormalizes(t *testing.T) {
	path := os.Getenv("NAUTHILUS_DOMAIN_AGE_POLICY_FILE")
	if path == "" {
		path = "examples/policy.json"
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = file.Close() }()

	document, err := policyconfig.Decode("json", file)
	if err != nil {
		t.Fatal(err)
	}

	normalized, err := configinput.Normalize(t.Context(), document)
	if err != nil {
		t.Fatal(err)
	}

	contributors, err := normalized.Contributors(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var activations []registry.TargetActivation

	for _, activation := range normalized.Activations {
		if activation.Target().Namespace() == "mail" {
			activations = append(activations, activation)
		}
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(contributors...).Compile(t.Context(), activations)
	if err != nil {
		t.Fatal(err)
	}

	bindings := referenceBindings(t)

	preparation, err := configinput.PrepareConfiguredNativeGeneration(t.Context(), configinput.ConfiguredNativeGenerationInput{Policy: document.Policy, Bindings: bindings, PostActionAcceptance: noPostActions{}})
	if err != nil {
		t.Fatal(err)
	}

	if err = preparation.Bindings.ValidateCatalog(catalog); err != nil {
		t.Fatal(err)
	}
}

// referenceBindings captures both actual native capabilities against a fixture artifact identity.
func referenceBindings(t *testing.T) *pluginruntime.GenerationBindings {
	t.Helper()

	path := filepath.Join(t.TempDir(), "domain-age.so")
	if err := os.WriteFile(path, []byte("fixture-artifact"), 0600); err != nil {
		t.Fatal(err)
	}

	digest, err := pluginloader.DigestArtifact(path)
	if err != nil {
		t.Fatal(err)
	}

	components := []pluginregistry.Component{
		{Value: assessment{}, DecisionFactProviderDescriptor: (assessment{}).Descriptor(), ModuleName: "domain_age", LocalName: "assessment", Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative},
		{Value: observation{}, DecisionEffectProviderDescriptor: (observation{}).Descriptor(), ModuleName: "domain_age", LocalName: "observation", Kind: pluginregistry.ComponentKindDecisionEffectProvider, Origin: pluginregistry.ComponentOriginNative},
	}

	bindings, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{Module: config.PluginModule{Name: "domain_age", Type: config.PluginModuleTypeGo, Path: path}, Descriptors: components, ArtifactPath: path, ArtifactDigest: digest, ModuleName: "domain_age", Status: pluginloader.ModuleStatusRegistered}})
	if err != nil {
		t.Fatal(err)
	}

	return bindings
}

// noPostActions rejects detached work because this example selects host-sync effects only.
type noPostActions struct{}

// Accept prevents accidental detached-effect activation in the reference-policy test.
func (noPostActions) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, errInput
}
