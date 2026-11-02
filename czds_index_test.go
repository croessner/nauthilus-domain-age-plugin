// Copyright (C) 2026 Christian Roessner
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// indexFixture writes the shared Python/Go format with valid integrity metadata.
func indexFixture(t *testing.T, path string, checked time.Time, corrupt bool) {
	t.Helper()

	hash := sha256.Sum256([]byte("new.com"))
	body := append(hash[:], make([]byte, 8)...)
	binary.BigEndian.PutUint64(body[32:], uint64(checked.Add(-time.Hour).Unix()))

	header := make([]byte, 128)
	copy(header, "CZDSIDX1")
	binary.BigEndian.PutUint64(header[8:], uint64(checked.Unix()))
	binary.BigEndian.PutUint64(header[16:], uint64(checked.Add(-24*time.Hour).Unix()))
	binary.BigEndian.PutUint64(header[24:], 1)
	copy(header[32:], "com")

	digest := sha256.Sum256(body)
	copy(header[48:], digest[:])

	if corrupt {
		body[0] ^= 1
	}

	if err := os.WriteFile(path, append(header, body...), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestCZDSIndex validates publication integrity and independent acquisition freshness.
func TestCZDSIndex(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "com.idx")
			checked := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
			indexFixture(t, path, checked, corrupt)

			file, err := openCZDSIndex(context.Background(), path, "com")
			if corrupt {
				if err == nil {
					t.Fatal("accepted corrupt index")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			found, err := file.search("new.com")
			if err != nil || !found.first.Equal(checked.Add(-time.Hour)) || !found.checked.Equal(checked) {
				t.Fatalf("lookup: %+v %v", found, err)
			}

			absent, err := file.search("old.com")
			if err != nil || !absent.first.IsZero() {
				t.Fatalf("baseline must remain unknown: %+v %v", absent, err)
			}
		})
	}
}

// TestCZDSLookupLatency bounds callers even when filesystem readers cannot progress.
func TestCZDSLookupLatency(t *testing.T) {
	store := &czdsStore{files: make(map[string]*czdsIndex), slots: make(chan struct{}, 4)}
	store.mu.Lock()
	defer store.mu.Unlock()

	started := time.Now()

	result := store.lookup(context.Background(), "new.com")
	if !result.first.IsZero() || time.Since(started) > time.Second {
		t.Fatal("disk stall escaped caller latency bound")
	}
}

// TestCZDSImportPrecedence keeps first-seen evidence independent of registration imports.
func TestCZDSImportPrecedence(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().Truncate(time.Second)
	checked := now.Add(-72 * time.Hour)
	indexFixture(t, filepath.Join(directory, "com.idx"), checked, false)

	store := &czdsStore{files: make(map[string]*czdsIndex), slots: make(chan struct{}, 4)}

	store.refresh(context.Background(), directory, nil)
	defer store.close()

	plugin := &Plugin{czds: store}
	values := make(map[string]any)
	plugin.mergeCZDS(context.Background(), values, "new.com", domainRecord{RegisteredAt: &now}, now, 48*time.Hour)

	if values[valueExternalFirstSeenState] != valueStale || values[valueExternalFirstSeenAgeSeconds] != int64(73*3600) {
		t.Fatalf("registration-only import suppressed independent CZDS evidence: %v", values)
	}

	values = make(map[string]any)
	plugin.mergeCZDS(context.Background(), values, "new.com", domainRecord{FirstSeen: &now}, now, 48*time.Hour)

	if len(values) != 0 {
		t.Fatal("CZDS replaced explicit imported first-seen evidence")
	}
}

// TestCZDSCollectorCompatibility reads evidence emitted by the actual Python collector.
func TestCZDSCollectorCompatibility(t *testing.T) {
	path := os.Getenv("NAUTHILUS_CZDS_TEST_INDEX")
	if path == "" {
		t.Skip("collector fixture not configured")
	}

	index, err := openCZDSIndex(context.Background(), path, "com")
	if err != nil {
		t.Fatal(err)
	}

	evidence, err := index.search("example.com")
	if err != nil || evidence.first.IsZero() || time.Since(evidence.first) < 30*time.Minute || time.Since(evidence.first) > 2*time.Hour {
		t.Fatalf("collector/native compatibility: %+v %v", evidence, err)
	}
}

// TestCZDSIndexRejectsTruncation exercises fixed-record boundary validation.
func TestCZDSIndexRejectsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.idx")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0}, 127), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := openCZDSIndex(context.Background(), path, "com"); err == nil {
		t.Fatal("accepted truncated header")
	}
}
