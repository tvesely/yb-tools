# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: yb/util/pb_util.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='yb/util/pb_util.proto',
  package='yb',
  syntax='proto2',
  serialized_options=b'\n\006org.yb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15yb/util/pb_util.proto\x12\x02yb\x1a google/protobuf/descriptor.proto\"[\n\x14\x43ontainerSupHeaderPB\x12\x32\n\x06protos\x18\x01 \x02(\x0b\x32\".google.protobuf.FileDescriptorSet\x12\x0f\n\x07pb_type\x18\x02 \x02(\tB\x08\n\x06org.yb'
  ,
  dependencies=[google_dot_protobuf_dot_descriptor__pb2.DESCRIPTOR,])




_CONTAINERSUPHEADERPB = _descriptor.Descriptor(
  name='ContainerSupHeaderPB',
  full_name='yb.ContainerSupHeaderPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='protos', full_name='yb.ContainerSupHeaderPB.protos', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pb_type', full_name='yb.ContainerSupHeaderPB.pb_type', index=1,
      number=2, type=9, cpp_type=9, label=2,
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
  serialized_start=63,
  serialized_end=154,
)

_CONTAINERSUPHEADERPB.fields_by_name['protos'].message_type = google_dot_protobuf_dot_descriptor__pb2._FILEDESCRIPTORSET
DESCRIPTOR.message_types_by_name['ContainerSupHeaderPB'] = _CONTAINERSUPHEADERPB
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ContainerSupHeaderPB = _reflection.GeneratedProtocolMessageType('ContainerSupHeaderPB', (_message.Message,), {
  'DESCRIPTOR' : _CONTAINERSUPHEADERPB,
  '__module__' : 'yb.util.pb_util_pb2'
  # @@protoc_insertion_point(class_scope:yb.ContainerSupHeaderPB)
  })
_sym_db.RegisterMessage(ContainerSupHeaderPB)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
