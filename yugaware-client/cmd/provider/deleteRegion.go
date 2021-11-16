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

package provider

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/flag"
	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/pkg/util"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/region_management"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func DeleteProviderRegionCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	options := &DeleteOptions{}
	cmd := &cobra.Command{
		Use:   "delete-region REGION",
		Short: "Delete a Yugabyte region",
		Long:  `Delete a Yugabyte region`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			options.RegionName = args[0]

			err = options.Validate(ctx)
			if err != nil {
				return err
			}

			return deleteProviderRegion(ctx, options)
		},
	}

	options.AddFlags(cmd)

	return cmd
}

func deleteProviderRegion(ctx *cmdutil.YWClientContext, options *DeleteOptions) error {
	log := ctx.Log

	if !options.Approve {
		err := util.ConfirmationDialog()
		if err != nil {
			return err
		}
	}

	params := options.GetProviderRegionDeleteParams(ctx)

	log.V(1).Info("deleting region", "region", options.RegionName, "uuid", options.region.UUID)
	task, err := ctx.Client.PlatformAPIs.RegionManagement.DeleteRegion(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	log.V(1).Info("delete region task", "task", task.GetPayload())

	table := &format.Output{
		OutputMessage: "Region Deleted",
		JSONObject:    task.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "SUCCESS", JSONPath: "$.success"},
		},
	}
	return table.Print()
}

type DeleteOptions struct {
	RegionName string

	Provider string `mapstructure:"provider,omitempty"`
	Approve  bool   `mapstructure:"approve,omitempty"`
	Force    bool   `mapstructure:"force,omitempty"`

	provider *models.Provider
	region   *models.Region
}

var _ cmdutil.CommandOptions = &DeleteOptions{}

func (o *DeleteOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringVar(&o.Provider, "provider", "", "Approve provider delete")
	flags.BoolVar(&o.Approve, "approve", false, "Approve delete without prompting")
	flags.BoolVar(&o.Force, "force", false, "Ignore errors and force universe deletion")

	flag.MarkFlagRequired("provider", flags)
}

func (o *DeleteOptions) Validate(ctx *cmdutil.YWClientContext) error {
	err := o.validateProviderName(ctx)
	if err != nil {
		return err
	}

	err = o.validateRegionName(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (o *DeleteOptions) Complete(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("required argument UNIVERSE_NAME is not set")
	}

	if len(args) > 1 {
		return fmt.Errorf("too many arguments")
	}

	o.RegionName = args[0]

	return nil
}

func (o *DeleteOptions) validateRegionName(ctx *cmdutil.YWClientContext) error {
	validateRegionNameError := func(err error) error {
		return fmt.Errorf(`unable to validate region "%s": %w`, o.RegionName, err)
	}

	if o.RegionName == "" {
		return validateRegionNameError(fmt.Errorf(`required argument REGION is not set`))
	}

	ctx.Log.V(1).Info("fetching regions")

	region, err := ctx.Client.GetRegionByIdentifier(o.provider.UUID, o.RegionName)
	if err != nil {
		return validateRegionNameError(err)
	}

	if region != nil {
		ctx.Log.V(1).Info("got region", "region", region)
		o.region = region
		return nil
	}

	return validateRegionNameError(fmt.Errorf(`region with name "%s" does not exist`, o.RegionName))
}

func (o *DeleteOptions) validateProviderName(ctx *cmdutil.YWClientContext) error {
	validateProviderNameError := func(err error) error {
		return fmt.Errorf(`unable to validate provider "%s": %w`, o.Provider, err)
	}

	if o.Provider == "" {
		return validateProviderNameError(fmt.Errorf(`required argument --provider is not set`))
	}

	ctx.Log.V(1).Info("fetching providers")

	provider, err := ctx.Client.GetProviderByIdentifier(o.Provider)
	if err != nil {
		return validateProviderNameError(err)
	}

	if provider != nil {
		ctx.Log.V(1).Info("got provider", "provider", provider)
		o.provider = provider
		return nil
	}

	return validateProviderNameError(fmt.Errorf(`provider with name "%s" does not exist`, o.Provider))
}

func (o *DeleteOptions) GetProviderRegionDeleteParams(ctx *cmdutil.YWClientContext) *region_management.DeleteRegionParams {
	return region_management.NewDeleteRegionParams().WithCUUID(ctx.Client.CustomerUUID()).
		WithPUUID(o.provider.UUID).
		WithRUUID(o.region.UUID)
}
