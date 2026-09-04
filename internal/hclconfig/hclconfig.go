/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package hclconfig provides shared helpers for parsing and validating
// HCL plugin configurations used by the SPIRE plugin.
package hclconfig

import (
	"fmt"

	"github.com/hashicorp/hcl"
)

// ParseHCL decodes an HCL configuration string into the provided struct pointer.
func ParseHCL[T any](hclString string) (*T, error) {
	cfg := new(T)
	if err := hcl.Decode(cfg, hclString); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}
	return cfg, nil
}

// FieldCheck pairs a field name with its current value for validation.
type FieldCheck struct {
	Name  string
	Value string
}

// ValidateRequired checks that none of the provided fields are empty.
// Returns an error listing all missing fields.
func ValidateRequired(fields ...FieldCheck) error {
	missing := make([]string, 0, len(fields))
	for _, f := range fields {
		if f.Value == "" {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %v", missing)
	}
	return nil
}
