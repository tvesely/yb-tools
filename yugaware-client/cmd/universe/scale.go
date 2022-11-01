package universe

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/yugabyte/yb-tools/pkg/flag"
	"github.com/yugabyte/yb-tools/pkg/format"
	"github.com/yugabyte/yb-tools/pkg/util"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/universe_cluster_mutations"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"

	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func ScaleCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	options := &ScaleOptions{}
	cmd := &cobra.Command{
		Use:   "scale (UNIVERSE_NAME|UNIVERSE_UUID) --nodes <count>",
		Short: "Scale up/down the number of nodes in a universe",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}

			// Positional argument
			options.Universe = args[0]

			err = options.Validate(ctx)
			if err != nil {
				return err
			}

			return scaleCommand(ctx, options)
		},
	}
	options.AddFlags(cmd)

	return cmd
}

type ScaleOptions struct {
	Universe string // Positional argument

	Nodes   int32 `mapstructure:"nodes,omitempty"`
	Approve bool  `mapstructure:"approve,omitempty"`

	Wait bool `mapstructure:"wait,omitempty"`

	universe *models.UniverseResp
}

var _ cmdutil.CommandOptions = &ScaleOptions{}

func (o *ScaleOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.Int32Var(&o.Nodes, "nodes", 0, "number of nodes to scale universe to")
	flags.BoolVar(&o.Approve, "approve", false, "approve scale up/down without prompting")

	flags.BoolVar(&o.Wait, "wait", false, "wait for scaling to complete")

	flag.MarkFlagsRequired([]string{"nodes"}, flags)
}

func (o *ScaleOptions) Validate(ctx *cmdutil.YWClientContext) error {
	err := o.validateUniverse(ctx)
	if err != nil {
		return err
	}

	return o.validateNodeCount()
}

func (o *ScaleOptions) validateUniverse(ctx *cmdutil.YWClientContext) error {
	validateUniverseError := func(err error) error {
		return fmt.Errorf(`unable to validate universe "%s": %w`, o.Universe, err)
	}
	var err error
	o.universe, err = ctx.Client.GetUniverseByIdentifier(o.Universe)
	if err != nil {
		return validateUniverseError(err)
	}

	if o.universe == nil {
		return validateUniverseError(errors.New(`universe does not exist`))
	}

	return nil
}

func (o *ScaleOptions) validateNodeCount() error {
	replicationFactor, err := o.getReplicationFactor()
	if err != nil {
		return err
	}
	if o.Nodes < replicationFactor {
		return fmt.Errorf(`node count "%d" must not be lower than the universe replication factor of "%d"`, o.Nodes, replicationFactor)
	}

	return nil
}

func (o *ScaleOptions) getReplicationFactor() (int32, error) {
	userIntent, err := o.clusterUserIntent()
	if err != nil {
		return 0, err
	}

	return userIntent.ReplicationFactor, nil
}

func (o *ScaleOptions) GetNodeCount() (int32, error) {
	userIntent, err := o.clusterUserIntent()
	if err != nil {
		return 0, err
	}

	return userIntent.NumNodes, nil
}

func (o *ScaleOptions) clusterUserIntent() (*models.UserIntent, error) {
	if len(o.universe.UniverseDetails.Clusters) < 1 {
		return nil, errors.New("universe cluster information is empty")
	}

	return o.universe.UniverseDetails.Clusters[0].UserIntent, nil
}

func (o *ScaleOptions) GetNewUpdatePrimaryClusterParams(ctx *cmdutil.YWClientContext) *universe_cluster_mutations.UpdatePrimaryClusterParams {
	clusters := o.universe.UniverseDetails.Clusters
	clusters[0].UserIntent.NumNodes = o.Nodes

	return universe_cluster_mutations.NewUpdatePrimaryClusterParams().
		WithCUUID(ctx.Client.CustomerUUID()).
		WithUniUUID(o.universe.UniverseUUID).
		WithUniverseConfigureTaskParams(&models.UniverseConfigureTaskParams{
			Clusters:     clusters,
			UniverseUUID: o.universe.UniverseUUID,
		})
}

func scaleCommand(ctx *cmdutil.YWClientContext, options *ScaleOptions) error {
	nodeCount, err := options.GetNodeCount()
	if err != nil {
		return err
	}

	if nodeCount == options.Nodes {
		ctx.Log.Info("the cluster node count is unchanged")
		return nil
	}

	if !options.Approve {
		ctx.Log.Info("scaling cluster", "current", nodeCount, "new", options.Nodes)
		err = util.ConfirmationDialog()
		if err != nil {
			return err
		}
	}

	params := options.GetNewUpdatePrimaryClusterParams(ctx)

	task, err := ctx.Client.PlatformAPIs.UniverseClusterMutations.UpdatePrimaryCluster(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return err
	}

	if options.Wait {
		err = cmdutil.WaitForTaskCompletion(ctx, ctx.Client, task.GetPayload())
		if err != nil {
			return err
		}
	}

	table := &format.Output{
		OutputMessage: "Scaled Universe",
		JSONObject:    task.GetPayload(),
		OutputType:    ctx.GlobalOptions.Output,
		TableColumns: []format.Column{
			{Name: "UNIVERSE_UUID", JSONPath: "$.resourceUUID"},
			{Name: "TASK_UUID", JSONPath: "$.taskUUID"},
		},
	}

	return table.Print()
}
