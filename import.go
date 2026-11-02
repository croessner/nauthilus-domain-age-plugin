// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// main validates and atomically installs normalized provider snapshots outside plugin mode.
func main() {
	input := flag.String("input", "", "normalized JSON snapshot")
	output := flag.String("output", "", "destination snapshot; omit for validation only")

	flag.Parse()

	if err := importSnapshot(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// importSnapshot shares runtime validation and replaces the destination only after durable writing.
func importSnapshot(input, output string) error {
	data, err := loadSnapshot(input)
	if err != nil {
		return err
	}

	if output == "" {
		return nil
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(output), ".domain-age-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(file.Name()) }()

	if _, err = file.Write(body); err != nil {
		_ = file.Close()
		return err
	}

	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}

	if err = file.Close(); err != nil {
		return err
	}

	return os.Rename(file.Name(), output)
}
