// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package main implements the native domain-age intelligence plugin.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const maxSnapshotBytes = 64 << 20

var errInput = errors.New("invalid domain-age input")

// domainRecord preserves distinct authoritative and observational timestamps.
type domainRecord struct {
	Domain              string     `json:"domain"`
	RegisteredAt        *time.Time `json:"registered_at,omitempty"`
	FirstSeen           *time.Time `json:"first_seen,omitempty"`
	RegisteredCheckedAt *time.Time `json:"registered_checked_at,omitempty"`
	FirstSeenCheckedAt  *time.Time `json:"first_seen_checked_at,omitempty"`
	RegisteredSource    string     `json:"registered_source,omitempty"`
	FirstSeenSource     string     `json:"first_seen_source,omitempty"`
}

// snapshot is an immutable, independently replaceable imported database.
type snapshot struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Records     []domainRecord `json:"records"`
	byDomain    map[string]domainRecord
}

// normalizeDomain returns the registrable ICANN domain, never a mailbox or address literal.
func normalizeDomain(input string) (string, error) {
	if input == "" || strings.TrimSpace(input) != input || strings.ContainsAny(input, "@:/[]\\\x00\r\n") {
		return "", errInput
	}

	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(input, "."))
	if err != nil || len(name) > 253 {
		return "", errInput
	}

	name = strings.ToLower(name)
	if _, err = netip.ParseAddr(name); err == nil {
		return "", errInput
	}

	for _, label := range strings.Split(name, ".") {
		if !validLabel(label) {
			return "", errInput
		}
	}

	_, icann := publicsuffix.PublicSuffix(name)
	if !icann {
		return "", errInput
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return "", errInput
	}

	return domain, nil
}

// decodeSnapshot validates the complete bounded import before making any record visible.
func decodeSnapshot(reader io.Reader, now time.Time) (*snapshot, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxSnapshotBytes+1))
	if err != nil || len(data) > maxSnapshotBytes {
		return nil, errInput
	}

	var result snapshot

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()

	if err = decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	if decoder.Decode(new(any)) != io.EOF || result.GeneratedAt.IsZero() || result.GeneratedAt.After(now) {
		return nil, errInput
	}

	result.byDomain = make(map[string]domainRecord, len(result.Records))
	for _, record := range result.Records {
		record, err = validateRecord(record, result.GeneratedAt)
		if err != nil {
			return nil, err
		}

		domain := record.Domain
		if _, exists := result.byDomain[domain]; exists {
			return nil, errInput
		}

		result.byDomain[domain] = record
	}

	return &result, nil
}

// loadSnapshot closes the file before returning a validated immutable snapshot.
func loadSnapshot(path string) (*snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return decodeSnapshot(file, time.Now())
}

// decodeRDAP accepts only a matching domain object with a coherent registration event.
func decodeRDAP(body []byte, domain string, now time.Time) (time.Time, error) {
	var object struct {
		Class  string `json:"objectClassName"`
		Domain string `json:"ldhName"`
		Events []struct {
			Action string    `json:"eventAction"`
			Date   time.Time `json:"eventDate"`
		} `json:"events"`
	}
	if json.Unmarshal(body, &object) != nil || object.Class != valueDomain || !strings.EqualFold(strings.TrimSuffix(object.Domain, "."), domain) {
		return time.Time{}, errInput
	}

	var registered time.Time

	for _, event := range object.Events {
		if event.Action != "registration" {
			continue
		}

		if event.Date.IsZero() || event.Date.After(now) || !registered.IsZero() {
			return time.Time{}, errInput
		}

		registered = event.Date
	}

	if registered.IsZero() {
		return time.Time{}, errInput
	}

	return registered, nil
}

// validLabel enforces the DNS hostname grammar after IDNA conversion.
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}

	return true
}

// validateRecord retains source acquisition times independently of snapshot publication.
func validateRecord(record domainRecord, generated time.Time) (domainRecord, error) {
	domain, err := normalizeDomain(record.Domain)
	if err != nil || !strings.EqualFold(strings.TrimSuffix(record.Domain, "."), domain) {
		return record, errInput
	}

	for _, evidence := range []struct {
		stamp, checked *time.Time
		source         string
	}{
		{record.RegisteredAt, record.RegisteredCheckedAt, record.RegisteredSource},
		{record.FirstSeen, record.FirstSeenCheckedAt, record.FirstSeenSource},
	} {
		if err := validateEvidence(evidence.stamp, evidence.checked, evidence.source, generated); err != nil {
			return record, err
		}
	}

	record.Domain = domain

	return record, nil
}

// validateEvidence checks acquisition provenance without refreshing it during republishing.
func validateEvidence(stamp, checked *time.Time, source string, generated time.Time) error {
	if stamp == nil {
		return nil
	}

	if checked == nil || checked.IsZero() || checked.After(generated) || stamp.IsZero() || stamp.After(*checked) {
		return errInput
	}

	if source == "" || len(source) > 128 || strings.ContainsAny(source, "\x00\r\n") {
		return errInput
	}

	return nil
}
