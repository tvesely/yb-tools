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

package backup

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/backups"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func ListCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	return &cobra.Command{
		Use:   "list (UNIVERSE_NAME|UNIVERSE_IDENTIFIER)",
		Short: "List backups for a Yugabyte universe",
		Long:  `List backups for a Yugabyte universe`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			universeName := args[0]

			return list(ctx, universeName)
		},
	}
}

func list(ctx *cmdutil.YWClientContext, universeName string) error {
	ctx.Log.V(1).Info("fetching universe", "universe", universeName)
	universe, err := ctx.Client.GetUniverseByIdentifier(universeName)
	if err != nil {
		return err
	}
	if universe == nil {
		return fmt.Errorf("universe %s does not exist", universeName)
	}

	ctx.Log.V(1).Info("fetching backups")
	params := backups.NewListOfBackupsParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID)

	backups, err := ctx.Client.PlatformAPIs.Backups.ListOfBackups(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	table := &format.Output{
		OutputMessage: "Backup List",
		JSONObject:    backups.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "BACKUP_UUID", JSONPath: "$.backupUUID"},
			{Name: "KEYSPACE", JSONPath: "$..keyspace"},
			{Name: "TABLES", Expr: "ignore_nulls(@..['tableName','tableNameList'])"},
			{Name: "TYPE", JSONPath: "$.backupInfo.backupType"},
			{Name: "STATE", JSONPath: "$.state"},
		},
	}
	return table.Print()
}
