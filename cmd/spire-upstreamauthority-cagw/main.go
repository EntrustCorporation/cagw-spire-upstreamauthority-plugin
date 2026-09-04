/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/pkg/upstreamauthority"
)

func main() {
	plugin := new(upstreamauthority.Plugin)

	// pluginmain.Serve registers the plugin with go-plugin, wires up the
	// logger and host services, and blocks until the plugin is terminated
	// by SPIRE.  It calls os.Exit on failure.
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
