package yugatool_test

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	. "github.com/icza/gox/gox"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/yugabyte/yb-tools/integration/util"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/common"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/consensus"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/master"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/tserver"
	"github.com/yugabyte/yb-tools/yugatool/cmd"
	"github.com/yugabyte/yb-tools/yugatool/pkg/client"
)

var _ = Describe("Yugatool Integration Tests", func() {
	Context("TLS connection", func() {
		When("listing cluster info", func() {
			var (
				err error
			)
			BeforeEach(func() {
				universe := CreateTLSTestUniverseIfNotExists()

				_, err = universe.RunYugatoolCommand("cluster_info")
			})
			It("returns successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Context("cluster_info", func() {
		When("listing cluster info", func() {
			var (
				command       []string
				clusterConfig master.SysClusterConfigEntryPB
				masterServers MasterServersReport
				tabletServers TabletServersReport
				tabletReports []*TabletReport
			)
			BeforeEach(func() {
				command = []string{"cluster_info", "-o", "json"}
			})
			JustBeforeEach(func() {
				universe := CreateTestUniverseIfNotExists()

				clusterInfo, err := universe.RunYugatoolCommand(command...)
				Expect(err).NotTo(HaveOccurred())
				dec := json.NewDecoder(clusterInfo)

				Expect(err).NotTo(HaveOccurred())

				Expect(dec.More()).To(BeTrue())
				err = dec.Decode(&clusterConfig)
				Expect(err).NotTo(HaveOccurred())

				Expect(dec.More()).To(BeTrue())
				err = dec.Decode(&masterServers)
				Expect(err).NotTo(HaveOccurred())

				Expect(dec.More()).To(BeTrue())
				err = dec.Decode(&tabletServers)
				Expect(err).NotTo(HaveOccurred())

				tabletReports = []*TabletReport{}
				for dec.More() {
					report := &TabletReport{}

					err = dec.Decode(&report)
					Expect(err).NotTo(HaveOccurred())
					tabletReports = append(tabletReports, report)
				}
			})
			It("returns successfully", func() {
				_, err := uuid.Parse(*clusterConfig.ClusterUuid)
				Expect(err).NotTo(HaveOccurred())

				for _, master := range masterServers.Content {
					_, err := uuid.Parse(string(master.InstanceId.PermanentUuid))
					Expect(err).NotTo(HaveOccurred())
				}

				for _, tserver := range tabletServers.Content {
					_, err := uuid.Parse(string(tserver.InstanceId.PermanentUuid))
					Expect(err).NotTo(HaveOccurred())
				}

				Expect(tabletReports).To(BeEmpty())
			})
			When("collecting tablet reports", func() {
				BeforeEach(func() {
					command = append(command, "--tablet-report")

					universe := CreateTestUniverseIfNotExists()

					db := universe.YSQLConnection()
					defer db.Close()

					_, err := db.Exec(`CREATE TABLE IF NOT EXISTS foo(a int);`)
					Expect(err).NotTo(HaveOccurred())
				})
				It("collects a tablet report from every tserver", func() {
					Expect(tabletReports).To(HaveLen(len(tabletServers.Content)))

					for _, report := range tabletReports {
						for _, tablet := range report.Content {
							_, err := uuid.Parse(tablet.Tablet.GetTabletStatus().GetTabletId())
							Expect(err).NotTo(HaveOccurred())
						}
					}
				})
				When("specifying a table name", func() {
					BeforeEach(func() {
						command = append(command, "--table", "foo")
					})
					It("only returns tablets for that table", func() {
						for _, report := range tabletReports {
							for _, tablet := range report.Content {
								Expect(tablet.Tablet.GetTabletStatus().GetTableName()).To(Equal("foo"))
							}
						}
					})
				})

				When("specifying a namespace", func() {
					BeforeEach(func() {
						command = append(command, "--namespace", "yugabyte")
					})
					It("only returns tablets for that namespace", func() {
						for _, report := range tabletReports {
							for _, tablet := range report.Content {
								Expect(tablet.Tablet.GetTabletStatus().GetNamespaceName()).To(Equal("yugabyte"))
							}
						}
					})
				})

				When("specifying a leaders only", func() {
					BeforeEach(func() {
						command = append(command, "--leaders-only")
					})
					It("only returns tablets that have the leader lease", func() {
						for _, report := range tabletReports {
							for _, tablet := range report.Content {
								Expect(tablet.ConsensusState.GetLeaderLeaseStatus()).To(Equal(consensus.LeaderLeaseStatus_HAS_LEASE))
							}
						}
					})
				})

				// TODO: This should be extracted into utility function to RemoveReplica()
				When("showing tombstoned tablets", func() {
					var universe *util.YugatoolContext
					BeforeEach(func() {
						command = append(command, "--show-tombstoned")

						universe = CreateTestUniverseIfNotExists()

						resp, err := universe.Master.MasterService.ChangeLoadBalancerState(&master.ChangeLoadBalancerStateRequestPB{
							IsEnabled: NewBool(false),
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(resp.Error).To(BeNil())

						nodes, errs := universe.AllTservers()
						for err := range errs {
							Expect(err).NotTo(HaveOccurred())
						}
						leader := nodes[0]

						listTabletsResponse, err := leader.TabletServerService.ListTabletsForTabletServer(&tserver.ListTabletsForTabletServerRequestPB{})
						Expect(err).NotTo(HaveOccurred())

						var tabletToDelete []byte
						for _, tablet := range listTabletsResponse.Entries {
							if tablet.GetTableName() == "foo" && tablet.GetIsLeader() {
								tabletToDelete = tablet.GetTabletId()
								break
							}
						}

						var follower *client.HostState
						for _, server := range nodes {
							listTabletsResponse, err := server.TabletServerService.ListTabletsForTabletServer(&tserver.ListTabletsForTabletServerRequestPB{})
							Expect(err).NotTo(HaveOccurred())

							for _, tablet := range listTabletsResponse.Entries {
								if string(tablet.GetTabletId()) == string(tabletToDelete) && !tablet.GetIsLeader() {
									follower = server
									break
								}
							}
						}
						Expect(follower).NotTo(BeNil())

						changeConfigType := consensus.ChangeConfigType_REMOVE_SERVER
						deleteType := common.TabletDataState_TABLET_DATA_TOMBSTONED

						changeConfigResp, err := leader.ConsensusService.ChangeConfig(&consensus.ChangeConfigRequestPB{
							DestUuid: leader.Status.NodeInstance.PermanentUuid,
							TabletId: tabletToDelete,
							Type:     &changeConfigType,
							Server:   &common.RaftPeerPB{PermanentUuid: follower.Status.NodeInstance.PermanentUuid},
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(changeConfigResp.Error).To(BeNil())

						deleteTabletResponse, err := follower.TabletServerAdminService.DeleteTablet(&tserver.DeleteTabletRequestPB{
							DestUuid:   follower.Status.NodeInstance.PermanentUuid,
							TabletId:   tabletToDelete,
							Reason:     NewString("retire a tablet for test"),
							DeleteType: &deleteType,
							HideOnly:   NewBool(false),
						})

						Expect(err).NotTo(HaveOccurred())
						Expect(deleteTabletResponse.Error).To(BeNil())

					})
					JustBeforeEach(func() {
						resp, err := universe.Master.MasterService.ChangeLoadBalancerState(&master.ChangeLoadBalancerStateRequestPB{
							IsEnabled: NewBool(true),
						})
						Expect(err).NotTo(HaveOccurred())
						Expect(resp.Error).To(BeNil())
					})
					It("returns tombstoned tablets", func() {
						hasTombstoned := false
						for _, report := range tabletReports {
							for _, tablet := range report.Content {
								if tablet.Tablet.GetTabletStatus().GetTabletDataState() == common.TabletDataState_TABLET_DATA_TOMBSTONED {
									hasTombstoned = true
								}
							}
						}
						Expect(hasTombstoned).To(BeTrue())
					})
				})
			})
		})
	})
	Context("util", func() {
		Context("identify_orphan_tables", func() {
			When("running the utility", func() {
				var (
					universe      *util.YugatoolContext
					command       []string
					yugatoolError error
				)
				BeforeEach(func() {
					command = []string{"util", "identify_orphaned_tables"}

					universe = CreateTestUniverseIfNotExists()
				})
				JustBeforeEach(func() {
					fmt.Println(command)
					_, yugatoolError = universe.RunYugatoolCommand(command...)
				})
				When("no tables exist in the database", func() {
					BeforeEach(func() {
						command = append(command, "--database", "postgres")
					})
					It("exits successfully", func() {
						// TODO: should check the logs to confirm that it did not see any tables
						Expect(yugatoolError).NotTo(HaveOccurred())
					})
				})
				When("no orphan tables exist in the database", func() {
					BeforeEach(func() {
						command = append(command, "--database", "yugabyte")
						db := universe.YSQLConnection()
						defer db.Close()

						_, err := db.Exec(`CREATE TABLE IF NOT EXISTS foo(a int);`)
						Expect(err).NotTo(HaveOccurred())
					})
					It("exits successfully", func() {
						// todo: confirm logs show that it did not find any orphan tables
						Expect(yugatoolError).NotTo(HaveOccurred())
					})
				})
				When("orphan tables exist in the database", func() {
					BeforeEach(func() {
						command = append(command, "--database", "yugabyte")
						db := universe.YSQLConnection()
						defer db.Close()

						//universe.SetMasterFlag("TEST_simulate_slow_table_create_secs", "10", true)
						//universe.SetMasterFlag("enable_transactional_ddl_gc", "false", true)
						//
						//hosts, errors := universe.AllTservers()
						//Expect(errors).To(HaveLen(0))
						//
						//for _, host := range hosts {
						//	universe.SetFlag(host, "TEST_user_ddl_operation_timeout_sec", "5", true)
						//}

						_, err := db.Exec(createFunctionPGDependType)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(createTypePGDependDescendants)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(createFunctionFindPGDependDescendants)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(createProcedureDeletePGDependObject)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(createProcedureDeleteTableObjects)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(`CREATE TABLE IF NOT EXISTS orphaned_table(a int);`)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(`set yb_non_ddl_txn_for_sys_tables_allowed to on;`)
						Expect(err).NotTo(HaveOccurred())

						_, err = db.Exec(`CALL pg_temp.delete_table_objects('orphaned_table'::regclass);`)
						Expect(err).NotTo(HaveOccurred())
					})
					AfterEach(func() {
						//universe.ResetFlags()
					})
					It("exits successfully", func() {
						Expect(yugatoolError).NotTo(HaveOccurred())
					})
				})
			})
		})
	})
})

type MasterServersReport struct {
	Message string                  `json:"msg"`
	Content []*common.ServerEntryPB `json:"content"`
}
type TabletServersReport struct {
	Message string                                      `json:"msg"`
	Content []*master.ListTabletServersResponsePB_Entry `json:"content"`
}

type TabletReport struct {
	Message string           `json:"msg"`
	Content []cmd.TabletInfo `json:"content"`
}

var createFunctionPGShdependType = `
CREATE OR REPLACE FUNCTION pg_temp.pg_shdepend_type(type char) RETURNS varchar AS
$$
BEGIN
    RETURN CASE
               WHEN type = 'o' THEN 'SHARED_DEPENDENCY_OWNER'
               WHEN type = 'a' THEN 'SHARED_DEPENDENCY_ACL'
               WHEN type = 'r' THEN 'SHARED_DEPENDENCY_POLICY'
               WHEN type = 'p' THEN 'SHARED_DEPENDENCY_PIN'
               WHEN type = 't' THEN 'SHARED_DEPENDENCY_TABLESPACE'
               ELSE 'unknown'
        END;
END;
$$ LANGUAGE plpgsql;
`

var createTypePGShdependDescendants = `

CREATE TYPE pg_temp.find_pg_shdepend_descendants AS
(
    database        name,
    dbid            oid,
    class           regclass,
    classid         oid,
    objid           oid,
    objsubid        int,
    refclass        regclass,
    refclassid      oid,
    refobjid        oid,
    deptype         "char",
    dependency_type varchar,
    level           int,
    row_number      bigint,
    path            text[]
);
`

var createFunctionFindPGShdependDescendants = `
CREATE OR REPLACE FUNCTION pg_temp.find_pg_shdepend_descendants(classid regclass, objid oid) RETURNS SETOF pg_temp.find_pg_shdepend_descendants AS
$$
BEGIN
    RETURN QUERY EXECUTE format(
        'WITH RECURSIVE pg_shdepend_tree AS (SELECT o.*, ARRAY [ARRAY [o.level || ''-'' || o.row_number, o.classid || ''-'' || o.objid]] AS path
                                             FROM (SELECT db.datname as database, p.dbid, p.classid::regclass AS class
                                                        , p.classid, p.objid, p.objsubid, p.refclassid::regclass as refclass
                                                        , p.refclassid, p.refobjid, p.deptype
                                                        , pg_temp.pg_shdepend_type(p.deptype::char) AS dependency_type
                                                        , 0 AS level, row_number() OVER (order by 1) AS row_number
                                                   FROM pg_catalog.pg_shdepend p
                                                            JOIN pg_database db
                                                                 ON p.dbid = db.oid AND db.datname = pg_catalog.current_database()
                                                   WHERE p.objid = %1$s
                                                     AND p.classid = %2$s) o
                                             UNION ALL
                                             SELECT c.database, c.dbid, c.class, c.classid, c.objid, c.objsubid, c.refclass
                                                  , c.refclassid, c.refobjid, c.deptype, c.dependency_type, c.level
                                                  , c.row_number, c.path || ARRAY [c.level || ''-'' || c.row_number
                                                 , c.classid || ''-'' || c.objid] AS path
                                             FROM (SELECT db.datname as database, n.dbid, n.classid::regclass AS class
                                                        , n.classid, n.objid, n.objsubid, n.refclassid::regclass as refclass
                                                        , n.refclassid, n.refobjid, n.deptype
                                                        , pg_temp.pg_shdepend_type(n.deptype::char) as dependency_type
                                                        , pg_shdepend_tree.level + 1 AS level
                                                        , row_number() OVER (ORDER BY level) as row_number
                                                        , pg_shdepend_tree.path
                                                   FROM pg_catalog.pg_shdepend n
                                                            JOIN pg_database db
                                                                 ON n.dbid = db.oid AND db.datname = pg_catalog.current_database()
                                                            JOIN pg_shdepend_tree ON pg_shdepend_tree.objid = n.refobjid and
                                                                                     pg_shdepend_tree.classid = n.refclassid) c)
         SELECT *
         FROM pg_shdepend_tree
         ORDER BY path;', objid, classid::oid);
    -- TODO: add an exception here?

    RETURN;
END ;
$$ LANGUAGE plpgsql;
`

var createFunctionPGDependType = `
CREATE OR REPLACE FUNCTION pg_temp.pg_depend_type(type char) RETURNS varchar AS
$$
BEGIN
    RETURN CASE
               WHEN type = 'n' THEN 'DEPENDENCY_NORMAL'
               WHEN type = 'a' THEN 'DEPENDENCY_AUTO'
               WHEN type = 'i' THEN 'DEPENDENCY_INTERNAL'
               WHEN type = 'I' THEN 'DEPENDENCY_INTERNAL_AUTO'
               WHEN type = 'e' THEN 'DEPENDENCY_EXTENSION'
               WHEN type = 'x' THEN 'DEPENDENCY_AUTO_EXTENSION'
               WHEN type = 'p' THEN 'DEPENDENCY_PIN'
               ELSE 'unknown'
        END;
END;
$$ LANGUAGE plpgsql;
`

var createTypePGDependDescendants = `
CREATE TYPE pg_temp.find_pg_depend_descendants AS
(
    class           regclass,
    classid         oid,
    objid           oid,
    objsubid        int,
    refclass        regclass,
    refclassid      oid,
    refobjid        oid,
    refobjsubid     int,
    deptype         "char",
    dependency_type varchar,
    level           int,
    row_number      bigint,
    path            text[]
);
`

var createFunctionFindPGDependDescendants = `
CREATE OR REPLACE FUNCTION pg_temp.find_pg_depend_descendants(classid regclass, objid oid) RETURNS SETOF pg_temp.find_pg_depend_descendants AS
$$
BEGIN
    RETURN QUERY EXECUTE format(
            'WITH RECURSIVE pg_depend_tree AS (SELECT o.*, ARRAY [ARRAY [o.level || ''-'' || o.row_number, o.classid || ''-'' || o.objid]] AS path
                                               FROM (SELECT p.classid::regclass AS class
                                                          , p.classid, p.objid, p.objsubid, p.refclassid::regclass as refclass
                                                          , p.refclassid, p.refobjid, p.refobjsubid, p.deptype
                                                          , pg_temp.pg_depend_type(p.deptype::char) AS dependency_type
                                                          , 0 AS level, row_number() OVER (order by 1) AS row_number
                                                     FROM pg_catalog.pg_depend p
                                                     WHERE p.objid = %1$s
                                                 AND p.classid = %2$s) o
                                               UNION ALL
                                               SELECT c.class, c.classid, c.objid, c.objsubid, c.refclass, c.refclassid
                                                    , c.refobjid, c.refobjsubid, c.deptype, c.dependency_type, c.level, c.row_number
                                                    , c.path || ARRAY [c.level || ''-'' || c.row_number
                                                   , c.classid || ''-'' || c.objid] AS path
                                               FROM (SELECT n.classid::regclass AS class
                                                          , n.classid, n.objid, n.objsubid, n.refclassid::regclass as refclass
                                                          , n.refclassid, n.refobjid, n.refobjsubid, n.deptype
                                                          , pg_temp.pg_depend_type(n.deptype::char) as dependency_type
                                                          , pg_depend_tree.level + 1 AS level
                                                          , row_number() OVER (ORDER BY level)
                                                          , pg_depend_tree.path
                                                     FROM pg_catalog.pg_depend n
                                                              JOIN pg_depend_tree ON pg_depend_tree.objid = n.refobjid and
                                                                                     pg_depend_tree.classid = n.refclassid) c)
             SELECT *
             FROM pg_depend_tree
             ORDER BY path;', objid, classid::oid);
    -- TODO: add an exception here?

    RETURN;
END ;
$$ LANGUAGE plpgsql;
`

var createTypePGDependMissingObjects = `
CREATE TYPE pg_temp.pg_depend_missing_objects AS
(
    catalog_table text,
    objid         oid
);
`

var createFunctionPGDependMissingObjects = `
CREATE OR REPLACE FUNCTION pg_temp.pg_depend_missing_objects() RETURNS SETOF pg_depend_missing_objects AS
$$
DECLARE
    catalog RECORD;
    result  RECORD;
BEGIN
    FOR catalog IN
        select oid, relname from pg_class where relnamespace = 11 and relhasoids
        LOOP
            RAISE DEBUG 'checking % for missing/dropped objects', catalog.relname;
            FOR result IN
                EXECUTE format('SELECT DISTINCT catalog_table, objid FROM
                                   (SELECT %1$L as catalog_table, objid
                                    FROM (SELECT objid
                                         FROM pg_catalog.pg_depend
                                         WHERE classid = %2$s
                                         UNION ALL
                                         SELECT refobjid
                                         FROM pg_catalog.pg_depend
                                         WHERE refclassid = %2$s) o
                                            LEFT OUTER JOIN %1$I c ON o.objid = c.oid
                                            WHERE c.oid IS null
                                   UNION ALL
                                   SELECT %1$L as catalog_table, objid
                                   FROM (SELECT dbid, objid
                                         FROM pg_catalog.pg_shdepend
                                         WHERE classid = %2$s
                                         UNION ALL
                                         SELECT dbid, refobjid
                                         FROM pg_catalog.pg_shdepend
                                         WHERE refclassid = %2$s) o
                                            JOIN pg_database db ON (o.dbid = db.oid AND db.datname = pg_catalog.current_database())
                                            LEFT OUTER JOIN %1$I c ON o.objid = c.oid
                                   WHERE c.oid IS null) q;', catalog.relname, catalog.oid)
                LOOP
                    RETURN NEXT result;
                END LOOP;
        END LOOP;
END ;
$$ LANGUAGE plpgsql;
`

var createFunctionYBCheckCatalog = `
CREATE OR REPLACE FUNCTION pg_temp.yb_check_catalog() RETURNS bool AS
$$
DECLARE
    missing_object   RECORD;
    reference_object find_pg_depend_descendants;
    result           bool = true;
BEGIN
    -- DEPENDENCY CHECK
    RAISE NOTICE 'pg_depend: checking for missing/dropped objects...';
    FOR missing_object IN
        SELECT * from pg_temp.pg_depend_missing_objects()
        LOOP
            result = false;
            RAISE WARNING '  found references to a dropped object class: % oid: %', missing_object.catalog_table, missing_object.objid;

            FOR reference_object IN
                SELECT * from pg_temp.find_pg_depend_descendants(missing_object.catalog_table, missing_object.objid)
                LOOP
                    RAISE INFO '       %->referencing object class: % classid: % objid: % deptype: % (%)', pg_catalog.repeat(' ', reference_object.level * 2), reference_object.class, reference_object.classid, reference_object.objid, pg_temp.pg_depend_type(reference_object.deptype::char), reference_object.deptype;
                END LOOP;

        END LOOP;

    -- TODO: check pg_index to see if there are any orphaned objects
    -- TODO: ADD pg_shdepend results to find_pg_depend_descendants
    -- TODO: check pg_attribute for orphaned attributes
    RETURN result;
END ;
$$ LANGUAGE plpgsql;
`

var createProcedureDeletePGDependObject = `
CREATE OR REPLACE PROCEDURE pg_temp.delete_pg_depend_object(classid regclass, objid regclass)
    LANGUAGE plpgsql
AS
$$
BEGIN
    EXECUTE format('DELETE FROM %1I WHERE oid = %2s', classid, objid::oid);
END;
$$;
`

var createProcedureDeleteTableObjects = `
CREATE OR REPLACE PROCEDURE pg_temp.delete_table_objects(table_oid oid)
    LANGUAGE plpgsql AS
$$
DECLARE
    descendant RECORD;
    is_index   BOOLEAN;
BEGIN
    FOR descendant IN
        SELECT classid, objid, objsubid, refclassid, refobjid, refobjsubid, deptype
        FROM pg_temp.find_pg_depend_descendants('pg_class', table_oid)
        group by classid, objid, objsubid, refclassid, refobjid, refobjsubid, deptype
        LOOP
            RAISE NOTICE 'deleting object: % %...', descendant.classid::regclass, descendant.objid;

            -- relation specific dependencies
            IF descendant.classid = 'pg_class'::regclass THEN
                RAISE NOTICE 'object is a relation, deleting dependant objects...';
                DELETE FROM pg_catalog.pg_attribute WHERE attrelid = descendant.objid;

                SELECT CASE WHEN relkind = 'i' then true else false END FROM pg_catalog.pg_class where oid = table_oid INTO is_index;

                IF is_index THEN
                    RAISE NOTICE 'object is index so remove from pg_index...';
                    -- Any indexes will have an entry in pg_index, while relations do not.
                    DELETE FROM pg_catalog.pg_index WHERE indexrelid = descendant.objid;
                ELSE
                    RAISE NOTICE 'object table so remove references from pg_shdepend...';
                    -- This should be the owner reference for the table
                    DELETE FROM pg_shdepend WHERE objid = descendant.objid AND classid = descendant.classid;
                END IF;
            END IF;

            CALL pg_temp.delete_pg_depend_object(descendant.classid, descendant.objid);

            DELETE
            FROM pg_catalog.pg_depend
            WHERE classid = descendant.classid
              and objid = descendant.objid
              and objsubid = descendant.objsubid
              and refclassid = descendant.refclassid
              and refobjid = descendant.refobjid
              and refobjsubid = descendant.refobjsubid
              and deptype = descendant.deptype;

        END LOOP;
END;
$$;

`
