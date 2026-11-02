// Copyright (C) 2026 Christian Roessner
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	api "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const czdsHeaderSize = 128
const czdsRecordSize = 40
const czdsMaxRecords = 10_000_000

var czdsZones = []string{"biz", "com", "info", "net", "online", "org", "shop", "site", "top", "xyz"}

// czdsIOBudget bounds uncancellable filesystem work across plugin generations.
var czdsIOBudget = make(chan struct{}, 4)

// czdsEvidence represents a collector observation, never a registration event.
type czdsEvidence struct{ first, checked time.Time }

// czdsIndex preserves validated immutable-file identity without retaining descriptors.
type czdsIndex struct {
	path    string
	info    os.FileInfo
	checked time.Time
	count   uint64
}

// czdsStore refreshes immutable descriptors outside the request path.
type czdsStore struct {
	files map[string]*czdsIndex
	slots chan struct{}
	mu    sync.RWMutex
}

// openCZDSIndex validates the entire publication before admitting any lookup.
func openCZDSIndex(ctx context.Context, path, zone string) (*czdsIndex, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	index, err := decodeCZDSIndex(ctx, file, zone)
	if err != nil {
		return nil, err
	}

	return index, nil
}

// decodeCZDSIndex checks fixed metadata, ordering, time bounds and record integrity.
func decodeCZDSIndex(ctx context.Context, file *os.File, zone string) (*czdsIndex, error) {
	header := make([]byte, czdsHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	checked := binary.BigEndian.Uint64(header[8:])
	baseline := binary.BigEndian.Uint64(header[16:])

	count := binary.BigEndian.Uint64(header[24:])
	if string(header[:8]) != "CZDSIDX1" || strings.TrimRight(string(header[32:48]), "\x00") != zone || count > czdsMaxRecords || checked > uint64(time.Now().Unix()) || baseline == 0 || baseline > checked || info.Size() != czdsHeaderSize+int64(count)*czdsRecordSize || !bytes.Equal(header[80:], make([]byte, 48)) {
		return nil, errInput
	}

	if err = validateCZDSRecords(ctx, file, header, count, baseline, checked); err != nil {
		return nil, err
	}

	return &czdsIndex{path: file.Name(), info: info, checked: time.Unix(int64(checked), 0), count: count}, nil
}

// validateCZDSRecords scans sequentially with bounded memory and cooperative cancellation.
func validateCZDSRecords(ctx context.Context, file *os.File, header []byte, count, baseline, checked uint64) error {
	digest := sha256.New()
	reader := io.TeeReader(bufio.NewReaderSize(file, 64<<10), digest)
	record := make([]byte, czdsRecordSize)
	previous := make([]byte, 32)

	for i := uint64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		if _, err := io.ReadFull(reader, record); err != nil {
			return err
		}

		stamp := binary.BigEndian.Uint64(record[32:])
		if (i > 0 && bytes.Compare(previous, record[:32]) >= 0) || stamp <= baseline || stamp > checked {
			return errInput
		}

		copy(previous, record[:32])
	}

	if !bytes.Equal(digest.Sum(nil), header[48:80]) {
		return errInput
	}

	return nil
}

// search performs logarithmic fixed-size reads against an admitted descriptor.
func (i *czdsIndex) search(domain string) (czdsEvidence, error) {
	file, err := os.Open(i.path)
	if err != nil {
		return czdsEvidence{}, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || !i.matches(info) {
		return czdsEvidence{}, errInput
	}

	hash := sha256.Sum256([]byte(domain))
	low, high := uint64(0), i.count
	record := make([]byte, czdsRecordSize)

	for low < high {
		mid := low + (high-low)/2
		if _, err := file.ReadAt(record, czdsHeaderSize+int64(mid)*czdsRecordSize); err != nil {
			return czdsEvidence{}, err
		}

		switch comparison := bytes.Compare(record[:32], hash[:]); {
		case comparison < 0:
			low = mid + 1
		case comparison > 0:
			high = mid
		default:
			return czdsEvidence{first: time.Unix(int64(binary.BigEndian.Uint64(record[32:])), 0), checked: i.checked}, nil
		}
	}

	return czdsEvidence{}, nil
}

// lookup bounds both caller latency and the number of potentially stalled filesystem reads.
func (s *czdsStore) lookup(ctx context.Context, domain string) czdsEvidence {
	select {
	case s.slots <- struct{}{}:
	default:
		return czdsEvidence{}
	}

	result := make(chan czdsEvidence, 1)

	started := startCZDSWork(func() {
		defer func() { <-s.slots }()

		s.mu.RLock()

		zone := domain[strings.LastIndexByte(domain, '.')+1:]
		index := s.files[zone]
		s.mu.RUnlock()

		evidence := czdsEvidence{}
		if index != nil {
			evidence, _ = index.search(domain)
		}

		result <- evidence
	})
	if !started {
		<-s.slots
		return czdsEvidence{}
	}

	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	select {
	case evidence := <-result:
		return evidence
	case <-ctx.Done():
		return czdsEvidence{}
	case <-timer.C:
		return czdsEvidence{}
	}
}

// refresh retains last-good descriptors if replacement files are absent or invalid.
func (s *czdsStore) refresh(ctx context.Context, directory string, logger api.Logger) {
	for _, zone := range czdsZones {
		if ctx.Err() != nil {
			return
		}

		path := filepath.Join(directory, zone+".idx")
		info, err := os.Stat(path)

		s.mu.RLock()
		current := s.files[zone]
		unchanged := err == nil && current.matches(info)

		s.mu.RUnlock()

		if unchanged || errors.Is(err, os.ErrNotExist) {
			continue
		}

		index, err := openCZDSIndex(ctx, path, zone)
		if err != nil {
			if logger != nil && ctx.Err() == nil {
				logger.Warn(ctx, "CZDS publication rejected; retaining last valid evidence", api.LogField{Key: "zone", Value: zone})
			}

			continue
		}

		s.mu.Lock()
		if ctx.Err() != nil {
			s.mu.Unlock()
			return
		}

		s.files[zone] = index
		s.mu.Unlock()
	}
}

// matches enforces the identity and metadata of the fully validated atomic publication.
func (i *czdsIndex) matches(info os.FileInfo) bool {
	return i != nil && os.SameFile(info, i.info) && info.Size() == i.info.Size() && info.ModTime().Equal(i.info.ModTime())
}

// close discards cached metadata without waiting for disk workers.
func (s *czdsStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files = make(map[string]*czdsIndex)
}

// startCZDS refreshes optional disk evidence using a cancellable host-owned task.
func (p *Plugin) startCZDS(host api.Host) {
	parent, cancel := context.WithCancel(context.Background())
	p.czdsCancel = cancel
	directory := p.config.CZDSDirectory

	host.Go(parent, "domain_age_czds_refresh", func(hostContext context.Context) error {
		ctx, release := context.WithCancel(hostContext)

		stop := context.AfterFunc(parent, release)
		defer stop()
		defer release()
		defer p.czds.close()

		timer := time.NewTimer(0)
		defer timer.Stop()

		refreshing := make(chan struct{}, 1)

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
				p.czds.scheduleRefresh(ctx, directory, host.Logger("domain_age"), refreshing)
				timer.Reset(time.Minute)
			}
		}
	})
}

// startCZDSWork caps filesystem workers independently of host supervisor lifetime.
func startCZDSWork(work func()) bool {
	select {
	case czdsIOBudget <- struct{}{}:
	default:
		return false
	}

	go func() {
		defer func() { <-czdsIOBudget }()

		work()
	}()

	return true
}

// scheduleRefresh keeps cancellable host supervision separate from bounded disk operations.
func (s *czdsStore) scheduleRefresh(ctx context.Context, directory string, logger api.Logger, refreshing chan struct{}) {
	select {
	case refreshing <- struct{}{}:
	default:
		return
	}

	if !startCZDSWork(func() {
		defer func() { <-refreshing }()

		s.refresh(ctx, directory, logger)
	}) {
		<-refreshing
	}
}

// mergeCZDS supplements only missing imported first-seen evidence with collector provenance.
func (p *Plugin) mergeCZDS(ctx context.Context, values map[string]any, domain string, record domainRecord, now time.Time, maxAge time.Duration) {
	if p.czds == nil || record.FirstSeen != nil {
		return
	}

	evidence := p.czds.lookup(ctx, domain)
	if evidence.first.IsZero() {
		return
	}

	values[valueExternalFirstSeenState] = valueKnown
	if now.Sub(evidence.checked) > maxAge {
		values[valueExternalFirstSeenState] = valueStale
	}

	values[valueExternalFirstSeenSource] = "czds-zone-observation"
	values[valueExternalFirstSeenAgeSeconds] = int64(now.Sub(evidence.first).Seconds())
	values[valueExternalDataAgeSeconds] = int64(now.Sub(evidence.checked).Seconds())
}
