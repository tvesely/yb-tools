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
package cmd

import (
	. "github.com/icza/gox/gox"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/flag"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/server"
	"github.com/yugabyte/yb-tools/yugatool/pkg/cmdutil"
)

func SetFlagCmd(ctx *cmdutil.YugatoolContext) *cobra.Command {
	options := &SetFlagOptions{}
	cmd := &cobra.Command{
		Use:   "set_flag",
		Short: "set a flag on all nodes",
		Long:  `set a flag on all nodes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}
			defer ctx.Client.Close()

			return setFlag(ctx, options)
		},
	}
	options.AddFlags(cmd)

	return cmd
}

type SetFlagOptions struct {
	Flag  string
	Value string
}

func (o *SetFlagOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&o.Flag, "flag", "f", "", "flag to set")
	flags.StringVarP(&o.Value, "value", "v", "", "value of flag")

	flag.MarkFlagsRequired([]string{"flag", "value"}, flags)
}

func (o *SetFlagOptions) Validate() error {
	return nil
}

var _ cmdutil.CommandOptions = &SetFlagOptions{}

func setFlag(ctx *cmdutil.YugatoolContext, options *SetFlagOptions) error {
	newFlag := &server.SetFlagRequestPB{
		Flag:  &options.Flag,
		Value: &options.Value,
		Force: NewBool(false),
	}

	log := ctx.Log.WithValues("newFlag", newFlag)
	for _, host := range ctx.Client.TServersUUIDMap {
		log.V(1).Info("setting flag", "newFlag", newFlag)
		response, err := host.GenericService.SetFlag(newFlag)
		if err != nil {
			log.Error(err, "could not set flag for host", "host", host.Status.GetNodeInstance())
			continue
		}

		if response.Result.Number() != server.SetFlagResponsePB_SUCCESS.Number() {
			return errors.Errorf("unable to set flag on %s: %s", host.Status.GetBoundRpcAddresses(), response)
		}
		log.Info("flag response", "response", response)
	}
	return nil
}
