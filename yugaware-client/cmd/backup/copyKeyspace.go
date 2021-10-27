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
	"time"

	. "github.com/icza/gox/gox"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/pkg/flag"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/backups"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/customer_configuration"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func CopyKeyspaceCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	options := &CopyKeyspaceOptions{}
	cmd := &cobra.Command{
		Use:   "copy-keyspace (UNIVERSE_NAME|UNIVERSE_UUID)",
		Short: "Copy all tables from one keyspace to another",
		Long:  `Copy all tables from one keyspace to another`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}

			options.UniverseName = args[0]

			err = options.Validate(ctx)
			if err != nil {
				return err
			}

			return copyKeyspace(ctx, options)
		},
	}
	options.AddFlags(cmd)

	return cmd
}

type CopyKeyspaceOptions struct {
	UniverseName string // positional arg

	Keyspace      string
	StorageConfig string
	ToUniverse    string
	ToKeyspace    string
	Parallelism   int32
}

func (o *CopyKeyspaceOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringVar(&o.Keyspace, "keyspace", "", "The keyspace to copy")
	flags.StringVar(&o.StorageConfig, "storage-config", "", "The storage type to use for the backup")
	flags.StringVar(&o.ToUniverse, "to-universe", "", "The name of the universe to copy the keyspace to")
	flags.StringVar(&o.ToKeyspace, "to-keyspace", "", "The keyspace name to use for the new tables")
	flags.Int32Var(&o.Parallelism, "parallelism", 3, "The number of threads for backup/restore (per node)")

	flag.MarkFlagsRequired([]string{"keyspace", "storage-config"}, flags)
}

func (o *CopyKeyspaceOptions) Validate(_ *cmdutil.YWClientContext) error {
	if o.ToUniverse == "" &&
		o.ToKeyspace == "" {
		return fmt.Errorf("--to-universe and/or --to-keyspace must be set")
	}
	return nil
}

var _ cmdutil.CommandOptions = &CopyKeyspaceOptions{}

func copyKeyspace(ctx *cmdutil.YWClientContext, options *CopyKeyspaceOptions) error {
	ctx.Log.V(1).Info("fetching universe", "universe", options.UniverseName)
	universe, err := ctx.Client.GetUniverseByIdentifier(options.UniverseName)
	if err != nil {
		return err
	}
	if universe == nil {
		return fmt.Errorf("universe %s does not exist", options.UniverseName)
	}
	ctx.Log.V(1).Info("got universe", "universe", universe)

	configParams := customer_configuration.NewGetListOfCustomerConfigParams().
		WithCUUID(ctx.Client.CustomerUUID())

	ctx.Log.V(1).Info("getting customer config", "params", configParams)
	configs, err := ctx.Client.PlatformAPIs.CustomerConfiguration.GetListOfCustomerConfig(configParams, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}
	ctx.Log.V(1).Info("got customer configs", "configs", configs.GetPayload())

	var storage *models.CustomerConfigUI
	for _, config := range configs.GetPayload() {
		if *config.Type == models.CustomerConfigTypeSTORAGE {
			if *config.Name == options.StorageConfig {
				storage = config
			}
		}
	}

	if storage == nil {
		return fmt.Errorf("unable to get storage type %s", options.StorageConfig)
	}

	var toUniverse *models.UniverseResp
	if options.ToUniverse != "" {
		ctx.Log.V(1).Info("fetching universe", "universe", options.ToUniverse)
		toUniverse, err = ctx.Client.GetUniverseByIdentifier(options.ToUniverse)
		if err != nil {
			return err
		}
		if toUniverse == nil {
			return fmt.Errorf("universe %s does not exist", options.ToUniverse)
		}
		ctx.Log.V(1).Info("got universe", "universe", toUniverse)
	}

	var nodeCount int32
	for _, node := range universe.UniverseDetails.NodeDetailsSet {
		if node.IsTserver {
			nodeCount++
		}
	}

	params := backups.NewCreateMultiTableBackupParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID).WithTableBackup(&models.MultiTableBackupRequestParams{
		ActionType:          NewString(models.BackupTableParamsActionTypeCREATE),
		BackupType:          models.BackupTableParamsBackupTypeYQLTABLETYPE,
		Keyspace:            options.Keyspace,
		Parallelism:         nodeCount * options.Parallelism,
		StorageConfigUUID:   &storage.ConfigUUID,
		TransactionalBackup: true,
		TimeBeforeDelete:    int64(48 * time.Hour / time.Millisecond), // Keep the backup around for 48 hours
	})

	ctx.Log.Info("creating backup", "params", params)
	task, err := ctx.Client.PlatformAPIs.Backups.CreateMultiTableBackup(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	completedTask, err := cmdutil.WaitForTaskCompletion(ctx, task.GetPayload())
	if err != nil {
		return err
	}
	ctx.Log.Info("backup complete", "task", completedTask)

	fetchBackupParams := backups.NewFetchBackupsByTaskUUIDParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(universe.UniverseUUID).
		WithTUUID(task.GetPayload().TaskUUID)

	backupsToRestore, err := ctx.Client.PlatformAPIs.Backups.FetchBackupsByTaskUUID(fetchBackupParams, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	restoreUniverse := universe.UniverseUUID
	restoreKeyspace := options.Keyspace
	if toUniverse != nil {
		restoreUniverse = toUniverse.UniverseUUID
	}
	if options.ToKeyspace != "" {
		restoreKeyspace = options.ToKeyspace
	}

	for _, backup := range backupsToRestore.GetPayload() {
		ctx.Log.Info("restoring backup", "to_universe", restoreUniverse, "to_keyspace", restoreKeyspace, "backup", backup.BackupInfo)
		restoreParams := backups.NewRestoreParams().
			WithCUUID(ctx.Client.CustomerUUID()).
			WithUniUUID(restoreUniverse).
			WithBackup(&models.BackupTableParams{
				StorageConfigUUID: backup.BackupInfo.StorageConfigUUID,
				StorageLocation:   backup.BackupInfo.StorageLocation,
				ActionType:        NewString(models.BackupTableParamsActionTypeRESTORE),
				Parallelism:       nodeCount * options.Parallelism,
				Keyspace:          restoreKeyspace,
			})

		task, err := ctx.Client.PlatformAPIs.Backups.Restore(restoreParams, ctx.Client.SwaggerAuth)
		if err != nil {
			return err
		}

		_, err = cmdutil.WaitForTaskCompletion(ctx, task.GetPayload())
		if err != nil {
			return err
		}
	}

	ctx.Log.Info("all tables have been copied", "from_universe", universe.UniverseUUID, "to_universe", restoreUniverse, "from_keypace", options.Keyspace, "to_keypace", restoreKeyspace)

	return nil
}
