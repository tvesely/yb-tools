package healthcheck

import (
	"bytes"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	. "github.com/icza/gox/gox"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/cdc"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/common"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/consensus"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/master"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/util"
	"github.com/yugabyte/yb-tools/yugatool/api/yugatool/healthcheck"
	"github.com/yugabyte/yb-tools/yugatool/pkg/client"
)

type TabletReport struct {
	*healthcheck.TabletReportPB

	Log    logr.Logger
	Client *client.YBClient
}

func NewTabletReport(logger logr.Logger, ybClient *client.YBClient, tabletLocations *master.TabletLocationsPB) *TabletReport {
	return &TabletReport{
		TabletReportPB: &healthcheck.TabletReportPB{
			Tablet:          NewString(string(tabletLocations.GetTabletId())),
			TabletLocations: tabletLocations,
		},
		Log:    logger.WithName("tablet_report").WithValues("tablet", string(tabletLocations.GetTabletId())),
		Client: ybClient,
	}
}

func (r *TabletReport) RunCheck() error {
	for _, replica := range r.GetTabletLocations().GetReplicas() {
		isMaster, err := isMasterUUID(r.Client, replica.GetTsInfo().GetPermanentUuid())
		if err != nil {
			return err
		}
		if isMaster {
			// TODO: checks for the master
			err := r.getMasterReplicaState(replica)
			if err != nil {
				return err
			}
			continue
		}

		replicaStatus, err := r.getTabletServerReplicaState(replica)
		if err != nil {
			return err
		}
		r.ReplicaStates = append(r.ReplicaStates, replicaStatus)
	}

	missingError := r.tabletLeaderCheck()
	if missingError != nil {
		r.Errors = &healthcheck.TabletReportPBErrorlist{MissingLeader: missingError}
	}
	return nil
}

// Check if the tablet has an active leader
func (r *TabletReport) tabletLeaderCheck() *healthcheck.TabletReportPBErrorlistMissingLeaderError {
	var bestMaster []byte
	foundLeader := false
	lastOpid := &util.OpIdPB{}

	r.Log.V(1).Info("leader check", "replicas", r.GetReplicaStates())
	for _, replica := range r.GetReplicaStates() {
		// Check if the tablet has an active lease
		if replica.GetConsensusState().GetError() == nil &&
			replica.GetConsensusState().GetLeaderLeaseStatus().Number() == consensus.LeaderLeaseStatus_HAS_LEASE.Number() {
			foundLeader = true
		}

		// save the tablet with the highest index
		if lastOpid.GetTerm() >= replica.GetOpid().GetTerm() &&
			lastOpid.GetIndex() >= replica.GetOpid().GetIndex() {
			bestMaster = replica.Uuid
		}

		lastOpid = replica.GetOpid()
	}
	if foundLeader {
		return nil
	}

	return &healthcheck.TabletReportPBErrorlistMissingLeaderError{BestLeaderUuid: NewString(string(bestMaster))}
}

// TODO: all masters should be cached in the client, so this should be handled internally by the client
func isMasterUUID(ybClient *client.YBClient, uuid []byte) (bool, error) {
	masters, err := ybClient.Master.MasterService.ListMasters(&master.ListMastersRequestPB{})
	if err != nil {
		return false, err
	}

	for _, m := range masters.GetMasters() {
		if bytes.Equal(m.GetInstanceId().GetPermanentUuid(), uuid) {
			return true, nil
		}
	}
	return false, nil
}

func (r *TabletReport) getTabletServerReplicaState(replica *master.TabletLocationsPB_ReplicaPB) (*healthcheck.TabletReportPBReplicaState, error) {
	replicaStatusError := func(err error) (*healthcheck.TabletReportPBReplicaState, error) {
		return &healthcheck.TabletReportPBReplicaState{}, fmt.Errorf("could not get tablet replica status: %w", err)
	}

	replicaStatus := &healthcheck.TabletReportPBReplicaState{Uuid: replica.GetTsInfo().PermanentUuid}

	tserverUUID, err := uuid.ParseBytes(replica.GetTsInfo().GetPermanentUuid())
	if err != nil {
		return replicaStatusError(err)
	}
	host, ok := r.Client.TServersUUIDMap[tserverUUID]
	if !ok {
		return replicaStatusError(fmt.Errorf("did not find server %s in client UUID map: %v", tserverUUID, r.Client.TServersUUIDMap))
	}

	latestEntryOpID, err := host.CDCService.GetLatestEntryOpId(&cdc.GetLatestEntryOpIdRequestPB{
		TabletId: r.GetTabletLocations().TabletId,
	})
	if err != nil {
		return replicaStatusError(err)
	}
	replicaStatus.Opid = latestEntryOpID.GetOpId()

	pb := consensus.GetConsensusStateRequestPB{
		DestUuid: host.Status.GetNodeInstance().GetPermanentUuid(),
		TabletId: r.GetTabletLocations().GetTabletId(),
		Type:     common.ConsensusConfigType_CONSENSUS_CONFIG_COMMITTED.Enum(),
	}
	consensusState, err := host.ConsensusService.GetConsensusState(&pb)
	if err != nil {
		return replicaStatusError(err)
	}

	replicaStatus.ConsensusState = consensusState

	r.Log.V(1).Info("got replica status", "status", replicaStatus)

	return replicaStatus, nil
}

func (r *TabletReport) getMasterReplicaState(replica *master.TabletLocationsPB_ReplicaPB) error {
	r.Log.V(1).Info("request to check master tablet is not yet implemented", "replica", replica)
	return nil
}

type TableReport struct {
	*healthcheck.TableReportPB

	Log    logr.Logger
	Client *client.YBClient
}

func NewTableReport(logger logr.Logger, ybClient *client.YBClient, tableInfo *master.ListTablesResponsePB_TableInfo) *TableReport {
	return &TableReport{
		TableReportPB: &healthcheck.TableReportPB{
			TableInfo: tableInfo,
		},
		Log:    logger.WithName("table_report").WithValues("table", tableInfo.GetName()),
		Client: ybClient,
	}
}

func (r *TableReport) RunCheck() error {
	tablets, err := r.Client.Master.MasterService.GetTableLocations(&master.GetTableLocationsRequestPB{
		Table: &master.TableIdentifierPB{
			TableId:   r.GetTableInfo().GetId(),
			TableName: r.GetTableInfo().Name,
			Namespace: r.GetTableInfo().Namespace,
		},
		RequireTabletsRunning: NewBool(true),
	})
	if err != nil {
		return err
	}

	if tablets.GetError() != nil {
		return fmt.Errorf("failed to get tablet locations: %s", tablets.GetError())
	}

	for _, tablet := range tablets.GetTabletLocations() {
		report := NewTabletReport(r.Log, r.Client, tablet)

		err := report.RunCheck()
		if err != nil {
			return err
		}

		r.Tablets = append(r.Tablets, report.TabletReportPB)
	}
	return nil
}
