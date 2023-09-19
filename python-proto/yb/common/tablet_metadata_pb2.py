# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: yb/common/tablet_metadata.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from yb.common import common_pb2 as yb_dot_common_dot_common__pb2
from yb.util import opid_pb2 as yb_dot_util_dot_opid__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='yb/common/tablet_metadata.proto',
  package='yb.tablet',
  syntax='proto2',
  serialized_options=b'\n\rorg.yb.tablet',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1fyb/common/tablet_metadata.proto\x12\tyb.tablet\x1a\x16yb/common/common.proto\x1a\x12yb/util/opid.proto\"\xdb\x02\n\x0bTableInfoPB\x12\x10\n\x08table_id\x18\x01 \x01(\x0c\x12\x16\n\x0enamespace_name\x18\n \x01(\t\x12\x12\n\ntable_name\x18\x02 \x01(\t\x12\x35\n\ntable_type\x18\x03 \x01(\x0e\x32\r.yb.TableType:\x12\x44\x45\x46\x41ULT_TABLE_TYPE\x12\x1c\n\x06schema\x18\x04 \x01(\x0b\x32\x0c.yb.SchemaPB\x12\x16\n\x0eschema_version\x18\x05 \x01(\r\x12/\n\x10partition_schema\x18\x06 \x01(\x0b\x32\x15.yb.PartitionSchemaPB\x12 \n\x07indexes\x18\x07 \x03(\x0b\x32\x0f.yb.IndexInfoPB\x12#\n\nindex_info\x18\x08 \x01(\x0b\x32\x0f.yb.IndexInfoPB\x12)\n\x0c\x64\x65leted_cols\x18\t \x03(\x0b\x32\x13.yb.DeletedColumnPB\"\xae\x02\n\rKvStoreInfoPB\x12\x13\n\x0bkv_store_id\x18\x01 \x02(\x0c\x12\x13\n\x0brocksdb_dir\x18\x02 \x01(\t\x12(\n\rrocksdb_files\x18\x03 \x03(\x0b\x32\x11.yb.tablet.FilePB\x12\x31\n\x0esnapshot_files\x18\x04 \x03(\x0b\x32\x19.yb.tablet.SnapshotFilePB\x12&\n\x06tables\x18\x05 \x03(\x0b\x32\x16.yb.tablet.TableInfoPB\x12\x17\n\x0flower_bound_key\x18\x06 \x01(\x0c\x12\x17\n\x0fupper_bound_key\x18\x07 \x01(\x0c\x12 \n\x18has_been_fully_compacted\x18\x08 \x01(\x08\x12\x1a\n\x12snapshot_schedules\x18\t \x03(\x0c\"\xf3\x07\n\x1cRaftGroupReplicaSuperBlockPB\x12\x18\n\x10primary_table_id\x18\x01 \x02(\x0c\x12\x15\n\rraft_group_id\x18\x02 \x02(\x0c\x12\"\n\tpartition\x18\r \x01(\x0b\x32\x0f.yb.PartitionPB\x12\x1b\n\x13OBSOLETE_table_name\x18\x07 \x01(\t\x12>\n\x13OBSOLETE_table_type\x18\x0f \x01(\x0e\x32\r.yb.TableType:\x12\x44\x45\x46\x41ULT_TABLE_TYPE\x12%\n\x0fOBSOLETE_schema\x18\x08 \x01(\x0b\x32\x0c.yb.SchemaPB\x12\x1f\n\x17OBSOLETE_schema_version\x18\t \x01(\r\x12\x38\n\x19OBSOLETE_partition_schema\x18\x0e \x01(\x0b\x32\x15.yb.PartitionSchemaPB\x12J\n\x11tablet_data_state\x18\n \x01(\x0e\x32\x1a.yb.tablet.TabletDataState:\x13TABLET_DATA_UNKNOWN\x12\x0f\n\x07wal_dir\x18\x12 \x01(\t\x12.\n\x1atombstone_last_logged_opid\x18\x0c \x01(\x0b\x32\n.yb.OpIdPB\x12*\n\x08kv_store\x18\x18 \x01(\x0b\x32\x18.yb.tablet.KvStoreInfoPB\x12\x1c\n\x14OBSOLETE_rocksdb_dir\x18\x10 \x01(\t\x12\x31\n\x16OBSOLETE_rocksdb_files\x18\x11 \x03(\x0b\x32\x11.yb.tablet.FilePB\x12:\n\x17OBSOLETE_snapshot_files\x18\x14 \x03(\x0b\x32\x19.yb.tablet.SnapshotFilePB\x12\x32\n\x15OBSOLETE_deleted_cols\x18\x13 \x03(\x0b\x32\x13.yb.DeletedColumnPB\x12)\n\x10OBSOLETE_indexes\x18\x15 \x03(\x0b\x32\x0f.yb.IndexInfoPB\x12,\n\x13OBSOLETE_index_info\x18\x16 \x01(\x0b\x32\x0f.yb.IndexInfoPB\x12/\n\x0fOBSOLETE_tables\x18\x17 \x03(\x0b\x32\x16.yb.tablet.TableInfoPB\x12\x18\n\tcolocated\x18\x19 \x01(\x08:\x05\x66\x61lse\x12\x35\n\x18\x63\x64\x63_min_replicated_index\x18\x1a \x01(\x03:\x13\x39\x32\x32\x33\x33\x37\x32\x30\x33\x36\x38\x35\x34\x37\x37\x35\x38\x30\x37\x12\"\n\x1ais_under_twodc_replication\x18\x1b \x01(\x08\x12\x0e\n\x06hidden\x18\x1c \x01(\x08J\x04\x08\x03\x10\x04J\x04\x08\x04\x10\x05J\x04\x08\x05\x10\x06J\x04\x08\x0b\x10\x0c\"9\n\x06\x46ilePB\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x12\n\nsize_bytes\x18\x02 \x01(\x04\x12\r\n\x05inode\x18\x03 \x01(\x04\"F\n\x0eSnapshotFilePB\x12\x1f\n\x04\x66ile\x18\x01 \x01(\x0b\x32\x11.yb.tablet.FilePB\x12\x13\n\x0bsnapshot_id\x18\x02 \x01(\x0c*\xcf\x01\n\x0fTabletDataState\x12\x18\n\x13TABLET_DATA_UNKNOWN\x10\xe7\x07\x12\x17\n\x13TABLET_DATA_COPYING\x10\x00\x12\x15\n\x11TABLET_DATA_READY\x10\x01\x12\x17\n\x13TABLET_DATA_DELETED\x10\x02\x12\x1a\n\x16TABLET_DATA_TOMBSTONED\x10\x03\x12\x1f\n\x1bTABLET_DATA_SPLIT_COMPLETED\x10\x04\x12\x1c\n\x18TABLET_DATA_INIT_STARTED\x10\x05*z\n\x10RaftGroupStatePB\x12\x0c\n\x07UNKNOWN\x10\xe7\x07\x12\x0f\n\x0bNOT_STARTED\x10\x05\x12\x11\n\rBOOTSTRAPPING\x10\x00\x12\x0b\n\x07RUNNING\x10\x01\x12\n\n\x06\x46\x41ILED\x10\x02\x12\r\n\tQUIESCING\x10\x03\x12\x0c\n\x08SHUTDOWN\x10\x04\x42\x0f\n\rorg.yb.tablet'
  ,
  dependencies=[yb_dot_common_dot_common__pb2.DESCRIPTOR,yb_dot_util_dot_opid__pb2.DESCRIPTOR,])

_TABLETDATASTATE = _descriptor.EnumDescriptor(
  name='TabletDataState',
  full_name='yb.tablet.TabletDataState',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_UNKNOWN', index=0, number=999,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_COPYING', index=1, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_READY', index=2, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_DELETED', index=3, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_TOMBSTONED', index=4, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_SPLIT_COMPLETED', index=5, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TABLET_DATA_INIT_STARTED', index=6, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1891,
  serialized_end=2098,
)
_sym_db.RegisterEnumDescriptor(_TABLETDATASTATE)

TabletDataState = enum_type_wrapper.EnumTypeWrapper(_TABLETDATASTATE)
_RAFTGROUPSTATEPB = _descriptor.EnumDescriptor(
  name='RaftGroupStatePB',
  full_name='yb.tablet.RaftGroupStatePB',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNKNOWN', index=0, number=999,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NOT_STARTED', index=1, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BOOTSTRAPPING', index=2, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RUNNING', index=3, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='FAILED', index=4, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='QUIESCING', index=5, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SHUTDOWN', index=6, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=2100,
  serialized_end=2222,
)
_sym_db.RegisterEnumDescriptor(_RAFTGROUPSTATEPB)

RaftGroupStatePB = enum_type_wrapper.EnumTypeWrapper(_RAFTGROUPSTATEPB)
TABLET_DATA_UNKNOWN = 999
TABLET_DATA_COPYING = 0
TABLET_DATA_READY = 1
TABLET_DATA_DELETED = 2
TABLET_DATA_TOMBSTONED = 3
TABLET_DATA_SPLIT_COMPLETED = 4
TABLET_DATA_INIT_STARTED = 5
UNKNOWN = 999
NOT_STARTED = 5
BOOTSTRAPPING = 0
RUNNING = 1
FAILED = 2
QUIESCING = 3
SHUTDOWN = 4



_TABLEINFOPB = _descriptor.Descriptor(
  name='TableInfoPB',
  full_name='yb.tablet.TableInfoPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='table_id', full_name='yb.tablet.TableInfoPB.table_id', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='namespace_name', full_name='yb.tablet.TableInfoPB.namespace_name', index=1,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='table_name', full_name='yb.tablet.TableInfoPB.table_name', index=2,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='table_type', full_name='yb.tablet.TableInfoPB.table_type', index=3,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=2,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='schema', full_name='yb.tablet.TableInfoPB.schema', index=4,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='schema_version', full_name='yb.tablet.TableInfoPB.schema_version', index=5,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='partition_schema', full_name='yb.tablet.TableInfoPB.partition_schema', index=6,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='indexes', full_name='yb.tablet.TableInfoPB.indexes', index=7,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='index_info', full_name='yb.tablet.TableInfoPB.index_info', index=8,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='deleted_cols', full_name='yb.tablet.TableInfoPB.deleted_cols', index=9,
      number=9, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=91,
  serialized_end=438,
)


_KVSTOREINFOPB = _descriptor.Descriptor(
  name='KvStoreInfoPB',
  full_name='yb.tablet.KvStoreInfoPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='kv_store_id', full_name='yb.tablet.KvStoreInfoPB.kv_store_id', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='rocksdb_dir', full_name='yb.tablet.KvStoreInfoPB.rocksdb_dir', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='rocksdb_files', full_name='yb.tablet.KvStoreInfoPB.rocksdb_files', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='snapshot_files', full_name='yb.tablet.KvStoreInfoPB.snapshot_files', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tables', full_name='yb.tablet.KvStoreInfoPB.tables', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='lower_bound_key', full_name='yb.tablet.KvStoreInfoPB.lower_bound_key', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='upper_bound_key', full_name='yb.tablet.KvStoreInfoPB.upper_bound_key', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='has_been_fully_compacted', full_name='yb.tablet.KvStoreInfoPB.has_been_fully_compacted', index=7,
      number=8, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='snapshot_schedules', full_name='yb.tablet.KvStoreInfoPB.snapshot_schedules', index=8,
      number=9, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=441,
  serialized_end=743,
)


_RAFTGROUPREPLICASUPERBLOCKPB = _descriptor.Descriptor(
  name='RaftGroupReplicaSuperBlockPB',
  full_name='yb.tablet.RaftGroupReplicaSuperBlockPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='primary_table_id', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.primary_table_id', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='raft_group_id', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.raft_group_id', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='partition', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.partition', index=2,
      number=13, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_table_name', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_table_name', index=3,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_table_type', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_table_type', index=4,
      number=15, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=2,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_schema', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_schema', index=5,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_schema_version', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_schema_version', index=6,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_partition_schema', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_partition_schema', index=7,
      number=14, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tablet_data_state', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.tablet_data_state', index=8,
      number=10, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=999,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='wal_dir', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.wal_dir', index=9,
      number=18, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tombstone_last_logged_opid', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.tombstone_last_logged_opid', index=10,
      number=12, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='kv_store', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.kv_store', index=11,
      number=24, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_rocksdb_dir', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_rocksdb_dir', index=12,
      number=16, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_rocksdb_files', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_rocksdb_files', index=13,
      number=17, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_snapshot_files', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_snapshot_files', index=14,
      number=20, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_deleted_cols', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_deleted_cols', index=15,
      number=19, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_indexes', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_indexes', index=16,
      number=21, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_index_info', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_index_info', index=17,
      number=22, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='OBSOLETE_tables', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.OBSOLETE_tables', index=18,
      number=23, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='colocated', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.colocated', index=19,
      number=25, type=8, cpp_type=7, label=1,
      has_default_value=True, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='cdc_min_replicated_index', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.cdc_min_replicated_index', index=20,
      number=26, type=3, cpp_type=2, label=1,
      has_default_value=True, default_value=9223372036854775807,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='is_under_twodc_replication', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.is_under_twodc_replication', index=21,
      number=27, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hidden', full_name='yb.tablet.RaftGroupReplicaSuperBlockPB.hidden', index=22,
      number=28, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=746,
  serialized_end=1757,
)


_FILEPB = _descriptor.Descriptor(
  name='FilePB',
  full_name='yb.tablet.FilePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='yb.tablet.FilePB.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='size_bytes', full_name='yb.tablet.FilePB.size_bytes', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='inode', full_name='yb.tablet.FilePB.inode', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1759,
  serialized_end=1816,
)


_SNAPSHOTFILEPB = _descriptor.Descriptor(
  name='SnapshotFilePB',
  full_name='yb.tablet.SnapshotFilePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='file', full_name='yb.tablet.SnapshotFilePB.file', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='snapshot_id', full_name='yb.tablet.SnapshotFilePB.snapshot_id', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1818,
  serialized_end=1888,
)

_TABLEINFOPB.fields_by_name['table_type'].enum_type = yb_dot_common_dot_common__pb2._TABLETYPE
_TABLEINFOPB.fields_by_name['schema'].message_type = yb_dot_common_dot_common__pb2._SCHEMAPB
_TABLEINFOPB.fields_by_name['partition_schema'].message_type = yb_dot_common_dot_common__pb2._PARTITIONSCHEMAPB
_TABLEINFOPB.fields_by_name['indexes'].message_type = yb_dot_common_dot_common__pb2._INDEXINFOPB
_TABLEINFOPB.fields_by_name['index_info'].message_type = yb_dot_common_dot_common__pb2._INDEXINFOPB
_TABLEINFOPB.fields_by_name['deleted_cols'].message_type = yb_dot_common_dot_common__pb2._DELETEDCOLUMNPB
_KVSTOREINFOPB.fields_by_name['rocksdb_files'].message_type = _FILEPB
_KVSTOREINFOPB.fields_by_name['snapshot_files'].message_type = _SNAPSHOTFILEPB
_KVSTOREINFOPB.fields_by_name['tables'].message_type = _TABLEINFOPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['partition'].message_type = yb_dot_common_dot_common__pb2._PARTITIONPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_table_type'].enum_type = yb_dot_common_dot_common__pb2._TABLETYPE
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_schema'].message_type = yb_dot_common_dot_common__pb2._SCHEMAPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_partition_schema'].message_type = yb_dot_common_dot_common__pb2._PARTITIONSCHEMAPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['tablet_data_state'].enum_type = _TABLETDATASTATE
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['tombstone_last_logged_opid'].message_type = yb_dot_util_dot_opid__pb2._OPIDPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['kv_store'].message_type = _KVSTOREINFOPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_rocksdb_files'].message_type = _FILEPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_snapshot_files'].message_type = _SNAPSHOTFILEPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_deleted_cols'].message_type = yb_dot_common_dot_common__pb2._DELETEDCOLUMNPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_indexes'].message_type = yb_dot_common_dot_common__pb2._INDEXINFOPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_index_info'].message_type = yb_dot_common_dot_common__pb2._INDEXINFOPB
_RAFTGROUPREPLICASUPERBLOCKPB.fields_by_name['OBSOLETE_tables'].message_type = _TABLEINFOPB
_SNAPSHOTFILEPB.fields_by_name['file'].message_type = _FILEPB
DESCRIPTOR.message_types_by_name['TableInfoPB'] = _TABLEINFOPB
DESCRIPTOR.message_types_by_name['KvStoreInfoPB'] = _KVSTOREINFOPB
DESCRIPTOR.message_types_by_name['RaftGroupReplicaSuperBlockPB'] = _RAFTGROUPREPLICASUPERBLOCKPB
DESCRIPTOR.message_types_by_name['FilePB'] = _FILEPB
DESCRIPTOR.message_types_by_name['SnapshotFilePB'] = _SNAPSHOTFILEPB
DESCRIPTOR.enum_types_by_name['TabletDataState'] = _TABLETDATASTATE
DESCRIPTOR.enum_types_by_name['RaftGroupStatePB'] = _RAFTGROUPSTATEPB
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TableInfoPB = _reflection.GeneratedProtocolMessageType('TableInfoPB', (_message.Message,), {
  'DESCRIPTOR' : _TABLEINFOPB,
  '__module__' : 'yb.common.tablet_metadata_pb2'
  # @@protoc_insertion_point(class_scope:yb.tablet.TableInfoPB)
  })
_sym_db.RegisterMessage(TableInfoPB)

KvStoreInfoPB = _reflection.GeneratedProtocolMessageType('KvStoreInfoPB', (_message.Message,), {
  'DESCRIPTOR' : _KVSTOREINFOPB,
  '__module__' : 'yb.common.tablet_metadata_pb2'
  # @@protoc_insertion_point(class_scope:yb.tablet.KvStoreInfoPB)
  })
_sym_db.RegisterMessage(KvStoreInfoPB)

RaftGroupReplicaSuperBlockPB = _reflection.GeneratedProtocolMessageType('RaftGroupReplicaSuperBlockPB', (_message.Message,), {
  'DESCRIPTOR' : _RAFTGROUPREPLICASUPERBLOCKPB,
  '__module__' : 'yb.common.tablet_metadata_pb2'
  # @@protoc_insertion_point(class_scope:yb.tablet.RaftGroupReplicaSuperBlockPB)
  })
_sym_db.RegisterMessage(RaftGroupReplicaSuperBlockPB)

FilePB = _reflection.GeneratedProtocolMessageType('FilePB', (_message.Message,), {
  'DESCRIPTOR' : _FILEPB,
  '__module__' : 'yb.common.tablet_metadata_pb2'
  # @@protoc_insertion_point(class_scope:yb.tablet.FilePB)
  })
_sym_db.RegisterMessage(FilePB)

SnapshotFilePB = _reflection.GeneratedProtocolMessageType('SnapshotFilePB', (_message.Message,), {
  'DESCRIPTOR' : _SNAPSHOTFILEPB,
  '__module__' : 'yb.common.tablet_metadata_pb2'
  # @@protoc_insertion_point(class_scope:yb.tablet.SnapshotFilePB)
  })
_sym_db.RegisterMessage(SnapshotFilePB)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
