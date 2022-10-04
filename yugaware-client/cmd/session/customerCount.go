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

package session

import (
	"fmt"

	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/session_management"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func CustomerCountCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "customer_count",
		Short: "Display the number of customers configured in the YW server",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			return customerCount(ctx)
		},
	}

	return cmd
}

func customerCount(ctx *cmdutil.YWClientContext) error {
	params := session_management.NewCustomerCountParams().
		WithDefaults()

	response, err := ctx.Client.PlatformAPIs.SessionManagement.CustomerCount(params)
	if err != nil {
		return err
	}
	if response == nil {
		return fmt.Errorf("unable to retrieve customer count: %w", err)
	}

	table := &format.Output{
		JSONObject: response.GetPayload(),
		OutputType: ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "COUNT", JSONPath: "$.count"},
		},
	}

	return table.Print()
}
