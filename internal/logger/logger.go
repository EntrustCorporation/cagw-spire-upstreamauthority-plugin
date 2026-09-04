/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package logger provides an embeddable logger mixin for SPIRE plugins
// that satisfies the pluginsdk.NeedsLogger interface.
package logger

import (
	"github.com/hashicorp/go-hclog"
)

// Loggable is an embeddable struct that provides a Logger field and a
// SetLogger method, satisfying pluginsdk.NeedsLogger.
type Loggable struct {
	Logger hclog.Logger
}

// SetLogger is called by the SPIRE plugin framework with a logger wired
// to SPIRE's logging facilities.
func (l *Loggable) SetLogger(logger hclog.Logger) {
	l.Logger = logger
}
