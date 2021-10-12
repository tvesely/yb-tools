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

package universe

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/universe_management"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func ResetUniverseVersionCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset_version UNIVERSE_NAME",
		Short: "Reset a universe cluster_info version",
		Long:  `Reset a universe cluster_info version`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			universeName := args[0]

			return resetUniverseVersion(ctx, universeName)
		},
	}

	return cmd
}

func resetUniverseVersion(ctx *cmdutil.YWClientContext, universeName string) error {
	universe, err := ctx.Client.GetUniverseByName(universeName)
	if err != nil {
		return err
	}

	if universe == nil {
		return fmt.Errorf("universe %s does not exist", universeName)
	}

	ctx.Log.V(1).Info("resetting universe version", "universe_name", universe.Name, "uuid", universe.UniverseUUID)
	params := universe_management.NewResetUniverseVersionParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID)

	task, err := ctx.Client.PlatformAPIs.UniverseManagement.ResetUniverseVersion(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	table := &format.Output{
		OutputMessage: "Reset Universe Version",
		JSONObject:    task.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "MESSAGE", JSONPath: "$.message"},
			{Name: "SUCCESS", JSONPath: "$.success"},
		},
	}
	return table.Print()
}
