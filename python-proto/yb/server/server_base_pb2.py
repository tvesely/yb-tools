# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: yb/server/server_base.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from yb.common import common_pb2 as yb_dot_common_dot_common__pb2
from yb.common import wire_protocol_pb2 as yb_dot_common_dot_wire__protocol__pb2
from yb.util import version_info_pb2 as yb_dot_util_dot_version__info__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='yb/server/server_base.proto',
  package='yb.server',
  syntax='proto2',
  serialized_options=b'\n\rorg.yb.server',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1byb/server/server_base.proto\x12\tyb.server\x1a\x16yb/common/common.proto\x1a\x1dyb/common/wire_protocol.proto\x1a\x1ayb/util/version_info.proto\"\xbf\x01\n\x0eServerStatusPB\x12)\n\rnode_instance\x18\x01 \x02(\x0b\x32\x12.yb.NodeInstancePB\x12+\n\x13\x62ound_rpc_addresses\x18\x02 \x03(\x0b\x32\x0e.yb.HostPortPB\x12,\n\x14\x62ound_http_addresses\x18\x03 \x03(\x0b\x32\x0e.yb.HostPortPB\x12\'\n\x0cversion_info\x18\x04 \x01(\x0b\x32\x11.yb.VersionInfoPB\"E\n\x10SetFlagRequestPB\x12\x0c\n\x04\x66lag\x18\x01 \x02(\t\x12\r\n\x05value\x18\x02 \x02(\t\x12\x14\n\x05\x66orce\x18\x03 \x01(\x08:\x05\x66\x61lse\"\xb7\x01\n\x11SetFlagResponsePB\x12\x31\n\x06result\x18\x01 \x02(\x0e\x32!.yb.server.SetFlagResponsePB.Code\x12\x0b\n\x03msg\x18\x02 \x01(\t\x12\x11\n\told_value\x18\x03 \x01(\t\"O\n\x04\x43ode\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x0b\n\x07SUCCESS\x10\x01\x12\x10\n\x0cNO_SUCH_FLAG\x10\x02\x12\r\n\tBAD_VALUE\x10\x03\x12\x0c\n\x08NOT_SAFE\x10\x04\"\x17\n\x15RefreshFlagsRequestPB\"\x18\n\x16RefreshFlagsResponsePB\" \n\x10GetFlagRequestPB\x12\x0c\n\x04\x66lag\x18\x01 \x01(\t\"7\n\x11GetFlagResponsePB\x12\x13\n\x05valid\x18\x01 \x01(\x08:\x04true\x12\r\n\x05value\x18\x02 \x01(\t\"\x18\n\x16\x46lushCoverageRequestPB\"*\n\x17\x46lushCoverageResponsePB\x12\x0f\n\x07success\x18\x01 \x01(\x08\"\x16\n\x14ServerClockRequestPB\",\n\x15ServerClockResponsePB\x12\x13\n\x0bhybrid_time\x18\x01 \x01(\x06\"\x14\n\x12GetStatusRequestPB\"@\n\x13GetStatusResponsePB\x12)\n\x06status\x18\x01 \x02(\x0b\x32\x19.yb.server.ServerStatusPB\"\x0f\n\rPingRequestPB\"\x10\n\x0ePingResponsePB2\xa4\x04\n\x0eGenericService\x12\x44\n\x07SetFlag\x12\x1b.yb.server.SetFlagRequestPB\x1a\x1c.yb.server.SetFlagResponsePB\x12\x44\n\x07GetFlag\x12\x1b.yb.server.GetFlagRequestPB\x1a\x1c.yb.server.GetFlagResponsePB\x12S\n\x0cRefreshFlags\x12 .yb.server.RefreshFlagsRequestPB\x1a!.yb.server.RefreshFlagsResponsePB\x12V\n\rFlushCoverage\x12!.yb.server.FlushCoverageRequestPB\x1a\".yb.server.FlushCoverageResponsePB\x12P\n\x0bServerClock\x12\x1f.yb.server.ServerClockRequestPB\x1a .yb.server.ServerClockResponsePB\x12J\n\tGetStatus\x12\x1d.yb.server.GetStatusRequestPB\x1a\x1e.yb.server.GetStatusResponsePB\x12;\n\x04Ping\x12\x18.yb.server.PingRequestPB\x1a\x19.yb.server.PingResponsePBB\x0f\n\rorg.yb.server'
  ,
  dependencies=[yb_dot_common_dot_common__pb2.DESCRIPTOR,yb_dot_common_dot_wire__protocol__pb2.DESCRIPTOR,yb_dot_util_dot_version__info__pb2.DESCRIPTOR,])



_SETFLAGRESPONSEPB_CODE = _descriptor.EnumDescriptor(
  name='Code',
  full_name='yb.server.SetFlagResponsePB.Code',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNKNOWN', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='SUCCESS', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NO_SUCH_FLAG', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='BAD_VALUE', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NOT_SAFE', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=495,
  serialized_end=574,
)
_sym_db.RegisterEnumDescriptor(_SETFLAGRESPONSEPB_CODE)


_SERVERSTATUSPB = _descriptor.Descriptor(
  name='ServerStatusPB',
  full_name='yb.server.ServerStatusPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='node_instance', full_name='yb.server.ServerStatusPB.node_instance', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='bound_rpc_addresses', full_name='yb.server.ServerStatusPB.bound_rpc_addresses', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='bound_http_addresses', full_name='yb.server.ServerStatusPB.bound_http_addresses', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='version_info', full_name='yb.server.ServerStatusPB.version_info', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=126,
  serialized_end=317,
)


_SETFLAGREQUESTPB = _descriptor.Descriptor(
  name='SetFlagRequestPB',
  full_name='yb.server.SetFlagRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='flag', full_name='yb.server.SetFlagRequestPB.flag', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='yb.server.SetFlagRequestPB.value', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='force', full_name='yb.server.SetFlagRequestPB.force', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=True, default_value=False,
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
  serialized_start=319,
  serialized_end=388,
)


_SETFLAGRESPONSEPB = _descriptor.Descriptor(
  name='SetFlagResponsePB',
  full_name='yb.server.SetFlagResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='result', full_name='yb.server.SetFlagResponsePB.result', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='msg', full_name='yb.server.SetFlagResponsePB.msg', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='old_value', full_name='yb.server.SetFlagResponsePB.old_value', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _SETFLAGRESPONSEPB_CODE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=391,
  serialized_end=574,
)


_REFRESHFLAGSREQUESTPB = _descriptor.Descriptor(
  name='RefreshFlagsRequestPB',
  full_name='yb.server.RefreshFlagsRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=576,
  serialized_end=599,
)


_REFRESHFLAGSRESPONSEPB = _descriptor.Descriptor(
  name='RefreshFlagsResponsePB',
  full_name='yb.server.RefreshFlagsResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=601,
  serialized_end=625,
)


_GETFLAGREQUESTPB = _descriptor.Descriptor(
  name='GetFlagRequestPB',
  full_name='yb.server.GetFlagRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='flag', full_name='yb.server.GetFlagRequestPB.flag', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
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
  serialized_start=627,
  serialized_end=659,
)


_GETFLAGRESPONSEPB = _descriptor.Descriptor(
  name='GetFlagResponsePB',
  full_name='yb.server.GetFlagResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='valid', full_name='yb.server.GetFlagResponsePB.valid', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=True, default_value=True,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='yb.server.GetFlagResponsePB.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
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
  serialized_start=661,
  serialized_end=716,
)


_FLUSHCOVERAGEREQUESTPB = _descriptor.Descriptor(
  name='FlushCoverageRequestPB',
  full_name='yb.server.FlushCoverageRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=718,
  serialized_end=742,
)


_FLUSHCOVERAGERESPONSEPB = _descriptor.Descriptor(
  name='FlushCoverageResponsePB',
  full_name='yb.server.FlushCoverageResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='yb.server.FlushCoverageResponsePB.success', index=0,
      number=1, type=8, cpp_type=7, label=1,
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
  serialized_start=744,
  serialized_end=786,
)


_SERVERCLOCKREQUESTPB = _descriptor.Descriptor(
  name='ServerClockRequestPB',
  full_name='yb.server.ServerClockRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=788,
  serialized_end=810,
)


_SERVERCLOCKRESPONSEPB = _descriptor.Descriptor(
  name='ServerClockResponsePB',
  full_name='yb.server.ServerClockResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='hybrid_time', full_name='yb.server.ServerClockResponsePB.hybrid_time', index=0,
      number=1, type=6, cpp_type=4, label=1,
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
  serialized_start=812,
  serialized_end=856,
)


_GETSTATUSREQUESTPB = _descriptor.Descriptor(
  name='GetStatusRequestPB',
  full_name='yb.server.GetStatusRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=858,
  serialized_end=878,
)


_GETSTATUSRESPONSEPB = _descriptor.Descriptor(
  name='GetStatusResponsePB',
  full_name='yb.server.GetStatusResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='yb.server.GetStatusResponsePB.status', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
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
  serialized_start=880,
  serialized_end=944,
)


_PINGREQUESTPB = _descriptor.Descriptor(
  name='PingRequestPB',
  full_name='yb.server.PingRequestPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=946,
  serialized_end=961,
)


_PINGRESPONSEPB = _descriptor.Descriptor(
  name='PingResponsePB',
  full_name='yb.server.PingResponsePB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
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
  serialized_start=963,
  serialized_end=979,
)

_SERVERSTATUSPB.fields_by_name['node_instance'].message_type = yb_dot_common_dot_wire__protocol__pb2._NODEINSTANCEPB
_SERVERSTATUSPB.fields_by_name['bound_rpc_addresses'].message_type = yb_dot_common_dot_common__pb2._HOSTPORTPB
_SERVERSTATUSPB.fields_by_name['bound_http_addresses'].message_type = yb_dot_common_dot_common__pb2._HOSTPORTPB
_SERVERSTATUSPB.fields_by_name['version_info'].message_type = yb_dot_util_dot_version__info__pb2._VERSIONINFOPB
_SETFLAGRESPONSEPB.fields_by_name['result'].enum_type = _SETFLAGRESPONSEPB_CODE
_SETFLAGRESPONSEPB_CODE.containing_type = _SETFLAGRESPONSEPB
_GETSTATUSRESPONSEPB.fields_by_name['status'].message_type = _SERVERSTATUSPB
DESCRIPTOR.message_types_by_name['ServerStatusPB'] = _SERVERSTATUSPB
DESCRIPTOR.message_types_by_name['SetFlagRequestPB'] = _SETFLAGREQUESTPB
DESCRIPTOR.message_types_by_name['SetFlagResponsePB'] = _SETFLAGRESPONSEPB
DESCRIPTOR.message_types_by_name['RefreshFlagsRequestPB'] = _REFRESHFLAGSREQUESTPB
DESCRIPTOR.message_types_by_name['RefreshFlagsResponsePB'] = _REFRESHFLAGSRESPONSEPB
DESCRIPTOR.message_types_by_name['GetFlagRequestPB'] = _GETFLAGREQUESTPB
DESCRIPTOR.message_types_by_name['GetFlagResponsePB'] = _GETFLAGRESPONSEPB
DESCRIPTOR.message_types_by_name['FlushCoverageRequestPB'] = _FLUSHCOVERAGEREQUESTPB
DESCRIPTOR.message_types_by_name['FlushCoverageResponsePB'] = _FLUSHCOVERAGERESPONSEPB
DESCRIPTOR.message_types_by_name['ServerClockRequestPB'] = _SERVERCLOCKREQUESTPB
DESCRIPTOR.message_types_by_name['ServerClockResponsePB'] = _SERVERCLOCKRESPONSEPB
DESCRIPTOR.message_types_by_name['GetStatusRequestPB'] = _GETSTATUSREQUESTPB
DESCRIPTOR.message_types_by_name['GetStatusResponsePB'] = _GETSTATUSRESPONSEPB
DESCRIPTOR.message_types_by_name['PingRequestPB'] = _PINGREQUESTPB
DESCRIPTOR.message_types_by_name['PingResponsePB'] = _PINGRESPONSEPB
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ServerStatusPB = _reflection.GeneratedProtocolMessageType('ServerStatusPB', (_message.Message,), {
  'DESCRIPTOR' : _SERVERSTATUSPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.ServerStatusPB)
  })
_sym_db.RegisterMessage(ServerStatusPB)

SetFlagRequestPB = _reflection.GeneratedProtocolMessageType('SetFlagRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _SETFLAGREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.SetFlagRequestPB)
  })
_sym_db.RegisterMessage(SetFlagRequestPB)

SetFlagResponsePB = _reflection.GeneratedProtocolMessageType('SetFlagResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _SETFLAGRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.SetFlagResponsePB)
  })
_sym_db.RegisterMessage(SetFlagResponsePB)

RefreshFlagsRequestPB = _reflection.GeneratedProtocolMessageType('RefreshFlagsRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _REFRESHFLAGSREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.RefreshFlagsRequestPB)
  })
_sym_db.RegisterMessage(RefreshFlagsRequestPB)

RefreshFlagsResponsePB = _reflection.GeneratedProtocolMessageType('RefreshFlagsResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _REFRESHFLAGSRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.RefreshFlagsResponsePB)
  })
_sym_db.RegisterMessage(RefreshFlagsResponsePB)

GetFlagRequestPB = _reflection.GeneratedProtocolMessageType('GetFlagRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _GETFLAGREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.GetFlagRequestPB)
  })
_sym_db.RegisterMessage(GetFlagRequestPB)

GetFlagResponsePB = _reflection.GeneratedProtocolMessageType('GetFlagResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _GETFLAGRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.GetFlagResponsePB)
  })
_sym_db.RegisterMessage(GetFlagResponsePB)

FlushCoverageRequestPB = _reflection.GeneratedProtocolMessageType('FlushCoverageRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _FLUSHCOVERAGEREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.FlushCoverageRequestPB)
  })
_sym_db.RegisterMessage(FlushCoverageRequestPB)

FlushCoverageResponsePB = _reflection.GeneratedProtocolMessageType('FlushCoverageResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _FLUSHCOVERAGERESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.FlushCoverageResponsePB)
  })
_sym_db.RegisterMessage(FlushCoverageResponsePB)

ServerClockRequestPB = _reflection.GeneratedProtocolMessageType('ServerClockRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _SERVERCLOCKREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.ServerClockRequestPB)
  })
_sym_db.RegisterMessage(ServerClockRequestPB)

ServerClockResponsePB = _reflection.GeneratedProtocolMessageType('ServerClockResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _SERVERCLOCKRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.ServerClockResponsePB)
  })
_sym_db.RegisterMessage(ServerClockResponsePB)

GetStatusRequestPB = _reflection.GeneratedProtocolMessageType('GetStatusRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _GETSTATUSREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.GetStatusRequestPB)
  })
_sym_db.RegisterMessage(GetStatusRequestPB)

GetStatusResponsePB = _reflection.GeneratedProtocolMessageType('GetStatusResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _GETSTATUSRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.GetStatusResponsePB)
  })
_sym_db.RegisterMessage(GetStatusResponsePB)

PingRequestPB = _reflection.GeneratedProtocolMessageType('PingRequestPB', (_message.Message,), {
  'DESCRIPTOR' : _PINGREQUESTPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.PingRequestPB)
  })
_sym_db.RegisterMessage(PingRequestPB)

PingResponsePB = _reflection.GeneratedProtocolMessageType('PingResponsePB', (_message.Message,), {
  'DESCRIPTOR' : _PINGRESPONSEPB,
  '__module__' : 'yb.server.server_base_pb2'
  # @@protoc_insertion_point(class_scope:yb.server.PingResponsePB)
  })
_sym_db.RegisterMessage(PingResponsePB)


DESCRIPTOR._options = None

_GENERICSERVICE = _descriptor.ServiceDescriptor(
  name='GenericService',
  full_name='yb.server.GenericService',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=982,
  serialized_end=1530,
  methods=[
  _descriptor.MethodDescriptor(
    name='SetFlag',
    full_name='yb.server.GenericService.SetFlag',
    index=0,
    containing_service=None,
    input_type=_SETFLAGREQUESTPB,
    output_type=_SETFLAGRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='GetFlag',
    full_name='yb.server.GenericService.GetFlag',
    index=1,
    containing_service=None,
    input_type=_GETFLAGREQUESTPB,
    output_type=_GETFLAGRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='RefreshFlags',
    full_name='yb.server.GenericService.RefreshFlags',
    index=2,
    containing_service=None,
    input_type=_REFRESHFLAGSREQUESTPB,
    output_type=_REFRESHFLAGSRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='FlushCoverage',
    full_name='yb.server.GenericService.FlushCoverage',
    index=3,
    containing_service=None,
    input_type=_FLUSHCOVERAGEREQUESTPB,
    output_type=_FLUSHCOVERAGERESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='ServerClock',
    full_name='yb.server.GenericService.ServerClock',
    index=4,
    containing_service=None,
    input_type=_SERVERCLOCKREQUESTPB,
    output_type=_SERVERCLOCKRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='GetStatus',
    full_name='yb.server.GenericService.GetStatus',
    index=5,
    containing_service=None,
    input_type=_GETSTATUSREQUESTPB,
    output_type=_GETSTATUSRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='Ping',
    full_name='yb.server.GenericService.Ping',
    index=6,
    containing_service=None,
    input_type=_PINGREQUESTPB,
    output_type=_PINGRESPONSEPB,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_GENERICSERVICE)

DESCRIPTOR.services_by_name['GenericService'] = _GENERICSERVICE

# @@protoc_insertion_point(module_scope)
