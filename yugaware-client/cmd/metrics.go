package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	. "github.com/icza/gox/gox"
	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/tcell"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/customer_management"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/cmdutil"
)

func MetricsCmd(ctx *cmdutil.YWClientContext) *cobra.Command {
	validArgs := []string{
		"cpu_usage_user",
		"cpu_usage_system",
		"disk_usage",
		"cpu_usage",
		"disk_iops",
		"tserver_rpcs_per_sec_by_universe",
		"memory_usage",
		"container_cpu_usage",
		"container_cpu_request",
		"container_cpu_usage_seconds_total",
		"container_memory_usage",
		"container_volume_stats",
		"container_volume_max_usage",
		"network_bytes",
		"network_packets",
		"network_errors",
		"system_load_over_time",
		"disk_bytes_per_second_per_node",
		"node_clock_skew",
		"redis_rpcs_per_sec_all",
		"redis_server_rpc_p95",
		"redis_server_rpc_p99",
		"redis_rpcs_per_sec_hash",
		"redis_rpcs_per_sec_ts",
		"redis_rpcs_per_sec_set",
		"redis_rpcs_per_sec_sortedset",
		"redis_rpcs_per_sec_str",
		"redis_rpcs_per_sec_local",
		"redis_ops_latency_all",
		"redis_ops_latency_hash",
		"redis_ops_latency_ts",
		"redis_ops_latency_set",
		"redis_ops_latency_sorted_set",
		"redis_ops_latency_str",
		"redis_ops_latency_local",
		"redis_yb_local_vs_remote_ops",
		"redis_yb_local_vs_remote_latency",
		"redis_reactor_latency",
		"tserver_ops_latency",
		"tserver_handler_latency",
		"total_rpcs_per_sec",
		"tserver_rpcs_per_sec_per_node",
		"tserver_consensus_rpcs_per_sec",
		"tserver_change_config",
		"tserver_remote_bootstraps",
		"tserver_consensus_rpcs_latency",
		"tserver_change_config_latency",
		"tserver_threads",
		"tserver_context_switches",
		"tserver_spinlock_server",
		"tserver_log_latency",
		"tserver_log_bytes_written",
		"tserver_log_bytes_read",
		"tserver_log_ops_second",
		"tserver_tc_malloc_stats",
		"tserver_log_stats",
		"tserver_cache_reader_num_ops",
		"tserver_glog_info_messages",
		"node_up",
		"lsm_rocksdb_num_seek_or_next",
		"lsm_rocksdb_num_seeks_per_node",
		"lsm_rocksdb_total_sst_per_node",
		"lsm_rocksdb_avg_num_sst_per_node",
		"lsm_rocksdb_blooms_checked_and_useful",
		"lsm_rocksdb_latencies_get",
		"lsm_rocksdb_latencies_write",
		"lsm_rocksdb_latencies_seek",
		"lsm_rocksdb_latencies_mutex",
		"lsm_rocksdb_block_cache_hit_miss",
		"lsm_rocksdb_block_cache_usage",
		"lsm_rocksdb_block_cache_add",
		"lsm_rocksdb_stalls",
		"lsm_rocksdb_write_rejections",
		"lsm_rocksdb_flush_size",
		"lsm_rocksdb_compaction",
		"lsm_rocksdb_compaction_numfiles",
		"lsm_rocksdb_compaction_time",
		"docdb_transaction",
		"ysql_server_rpc_per_second",
		"ysql_sql_latency",
		"ysql_server_advanced_rpc_per_second",
		"ysql_sql_advanced_latency",
		"ysql_server_rpc_p95",
		"ysql_server_rpc_p99",
		"cql_server_rpc_per_second",
		"cql_sql_latency",
		"cql_server_rpc_p95",
		"cql_server_rpc_p99",
		"cql_sql_latency_breakdown",
		"cql_yb_rpc_connections",
		"cql_yb_local_vs_remote",
		"cql_yb_latency",
		"cql_yb_transaction",
		"cql_reactor_latency",
		"response_sizes",
		"tserver_rpc_queue_size_master",
		"tserver_rpc_queue_size_tserver",
		"tserver_rpc_queue_size_cql",
		"tserver_rpc_queue_size_redis",
		"tserver_async_replication_lag_micros",
		"master_overall_rpc_rate",
		"master_get_tablet_location",
		"master_tsservice_reads",
		"master_tsservice_writes",
		"master_ts_heartbeats",
		"master_consensus_update",
		"master_table_ops",
		"master_cpu_util_secs",
		"tserver_cpu_util_secs",
		"redis_yb_rpc_connections",
		"tserver_yb_rpc_connections",
		"master_yb_rpc_connections",
	}
	cmd := &cobra.Command{
		Use:       "metrics",
		Short:     "metrics",
		Long:      `metrics`,
		Args:      cobra.MinimumNArgs(1),
		ValidArgs: validArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := cobra.OnlyValidArgs(cmd, args)
			if err != nil {
				return err
			}

			err = ctx.WithCmd(cmd).Setup()
			if err != nil {
				return err
			}

			for _, arg := range args {
				printMetrics(ctx, arg)
			}
			return nil
		},
	}
	return cmd
}

func printMetrics(ctx *cmdutil.YWClientContext, metric string) {
	t, err := tcell.New()
	if err != nil {
		panic(err)
	}
	defer t.Close()

	const redrawInterval = 5 * time.Second
	ctx, cancel := ctx.WithCancel()
	lc, err := linechart.New(
		linechart.AxesCellOpts(cell.FgColor(cell.ColorRed)),
		linechart.YLabelCellOpts(cell.FgColor(cell.ColorGreen)),
		linechart.XLabelCellOpts(cell.FgColor(cell.ColorCyan)),
	)
	if err != nil {
		panic(err)
	}
	go playLineChart(ctx, lc, redrawInterval/2, metric)
	c, err := container.New(
		t,
		container.Border(linestyle.Light),
		container.BorderTitle("PRESS Q TO QUIT"),
		container.PlaceWidget(lc),
	)
	if err != nil {
		panic(err)
	}

	quitter := func(k *terminalapi.Keyboard) {
		if k.Key == 'q' || k.Key == 'Q' {
			cancel()
		}
	}

	if err := termdash.Run(ctx, t, c, termdash.KeyboardSubscriber(quitter), termdash.RedrawInterval(redrawInterval)); err != nil {
		panic(err)
	}

}
func playLineChart(ctx *cmdutil.YWClientContext, lc *linechart.LineChart, delay time.Duration, metric string) {
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m, err := getMetrics(ctx, "", "", metric)
			if err != nil {
				panic(err)
			}

			if len(m) != 1 {
				panic(fmt.Sprintf("expected one metric, got %d", len(m)))
			}

			for _, chart := range m {
				for i, series := range chart.Data {
					if err = lc.Series(series.Name, series.GetY(),
						linechart.SeriesCellOpts(cell.FgColor(ColorList[i])),
						linechart.SeriesXLabels(map[int]string{
							0: "zero",
						}),
					); err != nil {
						panic(err)
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

var ColorList = []cell.Color{
	cell.ColorBlue,
	cell.ColorRGB24(255, 165, 0), // Orange
	cell.ColorGreen,
	cell.ColorRed,
	cell.ColorPurple,
	cell.ColorTeal,
	cell.ColorAqua,
	cell.ColorFuchsia,
}

type Metrics struct {
	Data      []Data `json:"data"`
	DirectURL *YWUrl  `json:"directURL,omitempty"`
	Layout    struct {
		Title string `json:"title"`
		Xaxis struct {
			Alias map[string]interface{} `json:"alias"`
			Type  string                 `json:"type"`
		} `json:"xaxis"`
		Yaxis struct {
			Alias      map[string]interface{} `json:"alias"`
			Ticksuffix string                 `json:"ticksuffix"`
		} `json:"yaxis"`
	} `json:"layout"`
	QueryKey string `json:"queryKey"`
}

func (m *Metrics) GetPromQLQuery() string {
	v := m.DirectURL.Query()
	return v.Get("g0.expr")
}

type Data struct { // TODO: data is not in a predictable format
	Name string        `json:"name"`
	Type string        `json:"type"`
	X    []interface{} `json:"x"`
	Y    []interface{} `json:"y"`
}

func (m *Data) GetX() []float64 {
	var vals []float64
	for _, datum := range m.X {
		switch v := datum.(type) {
		case int:
			vals = append(vals, float64(v))
		case float64:
			vals = append(vals, v)
		case string:
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				panic(err)
			}
			vals = append(vals, val)
		default:
			panic("can't convert X data - unknown type")
		}
	}
	return vals
}

func (m *Data) GetY() []float64 {
	var vals []float64
	for _, datum := range m.Y {
		switch v := datum.(type) {
		case int:
			vals = append(vals, float64(v))
		case float64:
			vals = append(vals, v)
		case string:
			val, err := strconv.ParseFloat(v, 64)
			if err != nil {
				panic(err)
			}
			vals = append(vals, val)
		default:
			panic("can't convert data - unknown type")
		}
	}
	return vals
}

func getMetrics(ctx *cmdutil.YWClientContext, nodePrefix string, nodeName string, chartNames ...string) (map[string]*Metrics, error) {
	params := customer_management.NewMetricsParams().
		WithCUUID(ctx.Client.CustomerUUID()).WithMetrics(&models.MetricQueryParams{
		Start:      NewInt64(time.Now().Unix() - 60*15),
		End:        time.Now().Unix(),
		Metrics:    chartNames,
		NodePrefix: nodePrefix,
		NodeName:   nodeName,
	})

	response, err := ctx.Client.PlatformAPIs.CustomerManagement.Metrics(params, ctx.Client.SwaggerAuth)
	if err != nil {
		return nil, err
	}

	metrics := map[string]*Metrics{}
	for name, unstructured := range response.GetPayload() {
		ctx.Log.V(1).Info("got metrics", "metrics", unstructured)
		bytes, err := json.Marshal(unstructured)
		if err != nil {
			return nil, err
		}

		m := &Metrics{}
		err = json.Unmarshal(bytes, m)
		if err != nil {
			return nil, err
		}

		metrics[name] = m
	}

	return metrics, nil
}

type YWUrl struct {
	*url.URL
}

func (u *YWUrl) MarshalJSON() ([]byte, error) {
	return []byte(u.String()), nil
}
func (u *YWUrl) UnmarshalJSON(in []byte) error {
	var err error
	u.URL, err = url.Parse(string(in))

	return err
}
