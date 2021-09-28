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
	"fmt"

	"github.com/blang/vfs"
	"github.com/go-logr/logr"
	. "github.com/icza/gox/gox"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/master"
	"github.com/yugabyte/yb-tools/yugatool/api/yugatool/config"
	"github.com/yugabyte/yb-tools/yugatool/cmd/util"
	"github.com/yugabyte/yb-tools/yugatool/pkg/client"
	"github.com/yugabyte/yb-tools/yugatool/pkg/healthcheck"
	cmdutil "github.com/yugabyte/yb-tools/yugaware-client/cmd/util"
)

var tabletCheckCmd = &cobra.Command{
	Use:   "tablet_check -m master-1[:port],master-2[:port]...",
	Short: "Check tablets for consistency issues",
	Long:  `Check tablets for consistency issues`,
	RunE:  tabletCheck,
}

func init() {
	rootCmd.AddCommand(tabletCheckCmd)
}

func tabletCheck(_ *cobra.Command, _ []string) error {
	log, err := util.GetLogger("tablet_check", debug)
	if err != nil {
		return err
	}

	hosts, err := util.ValidateHostnameList(masterAddresses, client.DefaultMasterPort)
	if err != nil {
		return err
	}

	ybclient := &client.YBClient{
		Log: log.WithName("client"),
		Fs:  vfs.OS(),
		Config: &config.UniverseConfigPB{
			Masters:        hosts,
			TimeoutSeconds: &dialTimeout,
			TlsOpts: &config.TlsOptionsPB{
				SkipHostVerification: &skipHostVerification,
				CaCertPath:           &caCert,
				CertPath:             &clientCert,
				KeyPath:              &clientKey,
			},
		},
	}

	err = ybclient.Connect()
	if err != nil {
		return err
	}
	defer ybclient.Close()

	return RunTabletCheck(log, ybclient)
}

func RunTabletCheck(log logr.Logger, ybclient *client.YBClient) error {
	tableReports, err := GetTableReports(log, ybclient)
	if err != nil {
		return err
	}

	for _, report := range tableReports {
		if shouldPrint(report) {
			// TODO: move the outputter to the top level
			output := cmdutil.OutputFormatter{
				OutputMessage: fmt.Sprintf("Tablet Report: %s", report.TableInfo),
				JSONObject:    report.GetTablets(),
				OutputType:    "table",
				TableColumns: []cmdutil.Column{
					{Name: "TABLET", JSONPath: "$.tablet"},
					//{Name: "TS_UUIDS", JSONPath: "$.tabletLocations.replicas[*].tsInfo.permanentUuid"},
					{Name: "TS_HOSTS", JSONPath: "$.tabletLocations.replicas[*].tsInfo.privateRpcAddresses[0].host"},
					{Name: "TS_ROLES", JSONPath: "$.replicaStates[*].consensusState.leaderLeaseStatus"},
					{Name: "OPIDS", JSONPath: "$.content[2].replicaStates[0].opid"},
					{Name: "BEST_LEADER", JSONPath: "$.errors.missingLeader.bestLeaderUuid"},
				},
			}

			if err := output.Print(); err != nil {
				return err
			}
		}
	}
	return nil
}

func shouldPrint(report *healthcheck.TableReport) bool {
	for _, tabletReport := range report.GetTablets() {
		if len(tabletReport.GetReplicaStates()) > 0 &&
			tabletReport.Errors != nil {
			return true
		}
	}
	return false
}

func GetTableReports(log logr.Logger, ybclient *client.YBClient) ([]*healthcheck.TableReport, error) {
	listTabletError := func(err error) ([]*healthcheck.TableReport, error) {
		return []*healthcheck.TableReport{}, fmt.Errorf("could not generate list of tablets: %w", err)
	}
	tables, err := ybclient.Master.MasterService.ListTables(&master.ListTablesRequestPB{
		ExcludeSystemTables: NewBool(false),
	})
	if err != nil {
		return listTabletError(err)
	}
	if tables.GetError() != nil {
		return listTabletError(errors.Errorf("failed to list tables: %s", tables.GetError()))
	}

	var tableReports []*healthcheck.TableReport
	for _, table := range tables.GetTables() {
		report := healthcheck.NewTableReport(log, ybclient, table)

		err := report.RunCheck()
		if err != nil {
			return listTabletError(err)
		}

		tableReports = append(tableReports, report)
	}
	return tableReports, nil
}
