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

package cmdutil

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/flag"
	"github.com/yugabyte/yb-tools/pkg/util"
)

type CommandOptions interface {
	AddFlags(cmd *cobra.Command)
	Validate(ctx *YBGetlogsContext) error
}

var _ CommandOptions = &GetLogsGlobalOptions{}

type GetLogsGlobalOptions struct {
	Debug  bool   `mapstructure:"debug"`
	Output string `mapstructure:"output"`
}

func (o *GetLogsGlobalOptions) AddFlags(cmd *cobra.Command) {
	// Global configuration flags
	flags := cmd.PersistentFlags()
	flags.BoolVar(&o.Debug, "debug", false, "debug mode")
	flags.StringVarP(&o.Output, "output", "o", "table", "Output options as one of: [table, json, yaml]")
}

func (o *GetLogsGlobalOptions) Validate(_ *YBGetlogsContext) error {
	return nil
}

type YBGetlogsContext struct {
	context.Context
	Log            logr.Logger
	Cmd            *cobra.Command
	GlobalOptions  *GetLogsGlobalOptions
	CommandOptions CommandOptions
}

func NewCommandContext() *YBGetlogsContext {
	return &YBGetlogsContext{
		Context: context.Background(),
	}
}

func (ctx *YBGetlogsContext) WithGlobalOptions(options *GetLogsGlobalOptions) *YBGetlogsContext {
	ctx.GlobalOptions = options
	return ctx
}

func (ctx *YBGetlogsContext) WithCmd(cmd *cobra.Command) *YBGetlogsContext {
	ctx.Cmd = cmd
	return ctx
}

func (ctx *YBGetlogsContext) WithOptions(options CommandOptions) *YBGetlogsContext {
	ctx.CommandOptions = options
	return ctx
}

func (ctx *YBGetlogsContext) Setup() error {
	if ctx.Cmd == nil ||
		ctx.GlobalOptions == nil {
		panic("command context is not set")
	}

	setupError := func(err error) error {
		return fmt.Errorf("failed to setup %s command: %w", ctx.Cmd.Name(), err)
	}

	var err error

	ctx.Log, err = util.GetLogger(ctx.Cmd.Name(), ctx.GlobalOptions.Debug)
	if err != nil {
		return setupError(err)
	}

	err = ctx.complete()
	if err != nil {
		return setupError(err)
	}

	err = flag.ValidateRequiredFlags(ctx.Cmd.Flags())
	if err != nil {
		return err
	}
	ctx.Cmd.SilenceUsage = true

	return nil
}

func (ctx *YBGetlogsContext) complete() error {
	flag.BindFlags(ctx.Cmd.Flags())
	err := flag.MergeConfigFile(ctx.Log, ctx.GlobalOptions)
	if err != nil {
		return err
	}

	if ctx.CommandOptions != nil {
		err := flag.MergeConfigFile(ctx.Log, ctx.CommandOptions)
		if err != nil {
			return err
		}
	}

	return nil
}
