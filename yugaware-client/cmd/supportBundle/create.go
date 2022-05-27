/*
Copyright © 2021-2022 Yugabyte Support

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
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func CreateCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	options := &CreateOptions{}

	cmd := &cobra.Command{
		Use:   "create (UNIVERSE_NAME|UNIVERSE_UUID)",
		Short: "Create a support bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			UniverseIdentifier := args[0]

			return create(ctx, UniverseIdentifier, options)
		},
	}
	options.AddFlags(cmd)

	return cmd
}

var _ cmdutil.CommandOptions = &CreateOptions{}

type CreateOptions struct {
	Wait bool `mapstructure:"wait,omitempty"`
}

func (o *CreateOptions) Validate(_ *cmdutil.YWClientContext) error {
	return nil
}

func (o *CreateOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.BoolVar(&o.Wait, "wait", false, "Wait for task completion")
}

func create(ctx *cmdutil.YWClientContext, universeIdentifier string, options *CreateOptions) error {
	universe, err := ctx.Client.GetUniverseByIdentifier(universeIdentifier)
	if err != nil {
		return err
	}

	if universe == nil {
		return fmt.Errorf("universe does not exist: %s", universeIdentifier)
	}

	params := support_bundle_management.NewCreateSupportBundleParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID).
		WithDummy(&models.DummyBody{})

	task, err := ctx.Client.PlatformAPIs.SupportBundleManagement.CreateSupportBundle(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("Unable to create support bundle: %w", err)
	}

	if options.Wait {
		err = cmdutil.WaitForTaskCompletion(ctx, ctx.Client, task.GetPayload())
		if err != nil {
			return err
		}
	}

	table := &format.Output{
		OutputMessage: "Bundle Created",
		JSONObject:    task.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "UNIVERSE_UUID", JSONPath: "$.resourceUUID"},
			{Name: "TASK_UUID", JSONPath: "$.taskUUID"},
		},
	}
	return table.Print()
}
