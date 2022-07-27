package util

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	. "github.com/icza/gox/gox"
	_ "github.com/lib/pq" // NOLINT
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/common"
	"github.com/yugabyte/yb-tools/yugatool/api/yb/master"
	"github.com/yugabyte/yb-tools/yugatool/pkg/client"
	"github.com/yugabyte/yb-tools/yugatool/pkg/client/session"
	"github.com/yugabyte/yb-tools/yugatool/pkg/cmdutil"
)

func IdentifyOrphanedTablesCmd(ctx *cmdutil.YugatoolContext) *cobra.Command {
	options := &ResetStatStatementsOptions{}
	cmd := &cobra.Command{
		Use:   "identify_orphaned_tables",
		Short: "Identify postgres tables that exist in the system.catalog, but not in the Postgres database",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := ctx.WithCmd(cmd).WithOptions(options).Setup()
			if err != nil {
				return err
			}
			defer ctx.Client.Close()

			return identifyOrphanedTables(ctx, ctx.Log, ctx.Client, options)
		},
	}
	options.AddFlags(cmd)

	return cmd
}

type IdentifyOrphanedTablesOptions struct {
	User     string `mapstructure:"user"`
	Database string `mapstructure:"database"`
	Password string `mapstructure:"password"`
}

var _ cmdutil.CommandOptions = &IdentifyOrphanedTablesOptions{}

func (o *IdentifyOrphanedTablesOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.StringVarP(&o.User, "user", "u", "postgres", "postgres username")
	flags.StringVar(&o.Database, "database", "postgres", "postgres password")
	flags.StringVarP(&o.Password, "password", "p", "", "postgres password")

	_ = viper.BindEnv("user", "PGUSER", "YB_USER")
	_ = viper.BindEnv("database", "PGDATABASE", "YB_DATABASE")
	_ = viper.BindEnv("password", "PGPASSWORD", "YB_PASSWORD")
}

func (o *IdentifyOrphanedTablesOptions) Validate() error {
	return nil
}

func identifyOrphanedTables(ctx *cmdutil.YugatoolContext, log logr.Logger, ybclient *client.YBClient, options *ResetStatStatementsOptions) error {
	log.Info("getting postgres hosts...")
	hosts, errors := ybclient.AllTservers()
	if len(errors) > 0 {
		for _, err := range errors {
			if x, ok := err.(session.DialError); ok {
				log.Error(x.Err, "could not dial host", "hostport", x.Host)
			} else {
				return err
			}
		}
	}

	for _, host := range hosts {
		hostport, err := getPostgresHostPort(log, ybclient, host.Status.NodeInstance.PermanentUuid)
		if err != nil {
			log.Error(err, "could not find postgres hostport")
			continue
		}

		encryptionEnabled, err := isPostgresEncryptionEnabled(ybclient, host.Status.NodeInstance.PermanentUuid)
		if err != nil {
			// not the end of the world, try to connect anyway
			log.Error(err, "could not determine if encryption is enabled")
		}

		err = doIdentifyOrphanedTables(ctx, log, ybclient, hostport, options, encryptionEnabled)
		if err != nil {
			log.Error(err, "failed to identify orphan tables")
		} else {
			return nil
		}
	}

	return nil
}

func doIdentifyOrphanedTables(ctx *cmdutil.YugatoolContext, log logr.Logger, ybclient *client.YBClient, host *common.HostPortPB, options *ResetStatStatementsOptions, encryptionEnabled bool) error {
	sslMode := "disable"
	if encryptionEnabled {
		sslMode = "require"
	}

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s",
		host.GetHost(), host.GetPort(), options.User, options.Database, sslMode)

	log = log.WithValues("host", host.GetHost(), "port", host.GetPort(), "user", options.User, "database", options.Database, "ssl", encryptionEnabled)
	log.Info("connecting to postgres host")

	if options.Password != "" {
		psqlInfo = fmt.Sprintf("%s password=%s", psqlInfo, options.Password)
	}
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	dattype := common.YQLDatabase_YQL_DATABASE_PGSQL

	tables, err := ybclient.Master.MasterService.ListTables(&master.ListTablesRequestPB{
		Namespace: &master.NamespaceIdentifierPB{
			Name:         &options.Database,
			DatabaseType: &dattype,
		},
		ExcludeSystemTables: NewBool(true),
		RelationTypeFilter:  nil,
	})
	if err != nil {
		return err
	}

	if tables.Error != nil {
		return fmt.Errorf("failed to list tables from master: %s", tables.GetError())
	}

	var oids []uint32
	oidToTableMap := map[uint32]*master.ListTablesResponsePB_TableInfo{}
	for _, table := range tables.GetTables() {
		if table.GetTableType() == common.TableType_PGSQL_TABLE_TYPE {
			tableID, err := uuid.Parse(string(table.Id))
			if err != nil {
				return err
			}

			// Postgres UUIDs should never exceed Uint32 sizes
			oidBytes := tableID.NodeID()
			oid := binary.BigEndian.Uint32(oidBytes[2:])
			oids = append(oids, oid)

			oidToTableMap[oid] = table

			log.V(1).Info("returned table", "table", table)
		}
	}

	if len(oids) < 1 {
		log.Info("no tables found in database")
		return nil
	}

	log.V(1).Info("returned postgres oids", "oids", oids)
	query := strings.Builder{}
	query.WriteString(`SELECT UNNEST(ARRAY[`)
	for i, oid := range oids {
		query.WriteString(strconv.FormatUint(uint64(oid), 10))
		if i+1 < len(oids) {
			query.WriteRune(',')
		}
	}

	query.WriteString(`]) EXCEPT SELECT oid FROM pg_class WHERE oid IN (`)

	for i, oid := range oids {
		query.WriteString(strconv.FormatUint(uint64(oid), 10))
		if i+1 < len(oids) {
			query.WriteRune(',')
		}
	}

	query.WriteRune(')')
	log.V(1).Info("identifying orphaned tables", "query", query.String())
	rows, err := db.Query(query.String())
	if err != nil {
		return err
	}

	var badOids []uint32
	for rows.Next() {
		var oid uint32
		err := rows.Scan(&oid)
		if err != nil {
			return err
		}

		badOids = append(badOids, oid)
	}

	if len(badOids) < 1 {
		log.Info("no orphan tables found")
		return nil
	}

	log.Info("found orphaned tables", "count", len(badOids), "oids", badOids)
	for _, oid := range badOids {
		if table, ok := oidToTableMap[oid]; ok {
			ctx.Cmd.Printf("# %s\n", table)
			if table.GetRelationType() == master.RelationType_USER_TABLE_RELATION {
				ctx.Cmd.Println("yb-admin --master_addresses ${MASTERS} ${CERTSDIR} delete_table_by_id " + string(table.GetId()))
			}
			if table.GetRelationType() == master.RelationType_INDEX_TABLE_RELATION {
				ctx.Cmd.Println("yb-admin --master_addresses ${MASTERS} ${CERTSDIR} delete_index_by_id " + string(table.GetId()))
			}
		}
	}

	return nil
}
