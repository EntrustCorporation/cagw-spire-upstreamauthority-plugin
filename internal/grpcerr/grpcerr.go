/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package grpcerr provides convenience wrappers around gRPC status errors
// used consistently across the plugin.
package grpcerr

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InvalidArgument returns a gRPC InvalidArgument error.
func InvalidArgument(msg string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, msg, args...)
}

// Internal returns a gRPC Internal error.
func Internal(msg string, args ...any) error {
	return status.Errorf(codes.Internal, msg, args...)
}

// NotConfigured returns a gRPC FailedPrecondition error indicating the plugin
// has not been configured yet.
func NotConfigured() error {
	return status.Error(codes.FailedPrecondition, "plugin not configured")
}

// Unimplemented returns a gRPC Unimplemented error.
func Unimplemented(msg string, args ...any) error {
	return status.Errorf(codes.Unimplemented, msg, args...)
}
