/*
Copyright © 2021 Yugabyte Support

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package supportBundle

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/support_bundle_management"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func ListCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	return &cobra.Command{
		Use:   "list (UNIVERSE_NAME|UNIVERSE_UUID)",
		Short: "List Yugabyte support bundles",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			UniverseIdentifier := args[0]

			return list(ctx, UniverseIdentifier)
		},
	}
}

func list(ctx *cmdutil.YWClientContext, universeIdentifier string) error {
	universe, err := ctx.Client.GetUniverseByIdentifier(universeIdentifier)
	if err != nil {
		return err
	}

	if universe == nil {
		return fmt.Errorf("universe does not exist: %s", universeIdentifier)
	}
	log := ctx.Log
	ywc := ctx.Client
	log.V(1).Info("listing support bundles")
	params := support_bundle_management.NewListSupportBundleParams().
		WithContext(ctx).
		WithCUUID(ywc.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID)

	supportBundles, err := ywc.PlatformAPIs.SupportBundleManagement.ListSupportBundle(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	table := &format.Output{
		OutputMessage: "Support Bundle List",
		JSONObject:    supportBundles.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "NAME", JSONPath: "$.name"},
			{Name: "UNIVERSE_UUID", JSONPath: "$.universeUUID"},
			{Name: "CLOUD", JSONPath: "$.universeDetails.clusters[0].placementInfo.cloudList[0].code"},
			{Name: "REGIONS", JSONPath: "$.universeDetails.clusters[0].regions[*].code"},
			{Name: "INSTANCE_TYPE", JSONPath: "$.universeDetails.clusters[0].userIntent.instanceType"},
			{Name: "RF", JSONPath: "$.universeDetails.clusters[0].userIntent.replicationFactor"},
			{Name: "NODE_COUNT", JSONPath: "$.universeDetails.clusters[0].userIntent.numNodes"},
			{Name: "VERSION", JSONPath: "$.universeDetails.clusters[0].userIntent.ybSoftwareVersion"},
		},
	}
	return table.Print()
}
