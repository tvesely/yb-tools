# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: yb/util/proto_container_test2.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from yb.util import proto_container_test_pb2 as yb_dot_util_dot_proto__container__test__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='yb/util/proto_container_test2.proto',
  package='yb',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n#yb/util/proto_container_test2.proto\x12\x02yb\x1a\"yb/util/proto_container_test.proto\"A\n\x15ProtoContainerTest2PB\x12(\n\x06record\x18\x01 \x02(\x0b\x32\x18.yb.ProtoContainerTestPB\"b\n\x14TestObjectRequiredPB\x12\x0f\n\x07string1\x18\x01 \x02(\t\x12(\n\x06record\x18\x02 \x02(\x0b\x32\x18.yb.TestStringRequiredPB\x12\x0f\n\x07string2\x18\x03 \x02(\t\"b\n\x14TestObjectRepeatedPB\x12\x0f\n\x07string1\x18\x01 \x03(\t\x12(\n\x06record\x18\x02 \x03(\x0b\x32\x18.yb.TestStringRepeatedPB\x12\x0f\n\x07string2\x18\x03 \x03(\t'
  ,
  dependencies=[yb_dot_util_dot_proto__container__test__pb2.DESCRIPTOR,])




_PROTOCONTAINERTEST2PB = _descriptor.Descriptor(
  name='ProtoContainerTest2PB',
  full_name='yb.ProtoContainerTest2PB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='record', full_name='yb.ProtoContainerTest2PB.record', index=0,
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
  serialized_start=79,
  serialized_end=144,
)


_TESTOBJECTREQUIREDPB = _descriptor.Descriptor(
  name='TestObjectRequiredPB',
  full_name='yb.TestObjectRequiredPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='string1', full_name='yb.TestObjectRequiredPB.string1', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='record', full_name='yb.TestObjectRequiredPB.record', index=1,
      number=2, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='string2', full_name='yb.TestObjectRequiredPB.string2', index=2,
      number=3, type=9, cpp_type=9, label=2,
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
  serialized_start=146,
  serialized_end=244,
)


_TESTOBJECTREPEATEDPB = _descriptor.Descriptor(
  name='TestObjectRepeatedPB',
  full_name='yb.TestObjectRepeatedPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='string1', full_name='yb.TestObjectRepeatedPB.string1', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='record', full_name='yb.TestObjectRepeatedPB.record', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='string2', full_name='yb.TestObjectRepeatedPB.string2', index=2,
      number=3, type=9, cpp_type=9, label=3,
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
  serialized_start=246,
  serialized_end=344,
)

_PROTOCONTAINERTEST2PB.fields_by_name['record'].message_type = yb_dot_util_dot_proto__container__test__pb2._PROTOCONTAINERTESTPB
_TESTOBJECTREQUIREDPB.fields_by_name['record'].message_type = yb_dot_util_dot_proto__container__test__pb2._TESTSTRINGREQUIREDPB
_TESTOBJECTREPEATEDPB.fields_by_name['record'].message_type = yb_dot_util_dot_proto__container__test__pb2._TESTSTRINGREPEATEDPB
DESCRIPTOR.message_types_by_name['ProtoContainerTest2PB'] = _PROTOCONTAINERTEST2PB
DESCRIPTOR.message_types_by_name['TestObjectRequiredPB'] = _TESTOBJECTREQUIREDPB
DESCRIPTOR.message_types_by_name['TestObjectRepeatedPB'] = _TESTOBJECTREPEATEDPB
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ProtoContainerTest2PB = _reflection.GeneratedProtocolMessageType('ProtoContainerTest2PB', (_message.Message,), {
  'DESCRIPTOR' : _PROTOCONTAINERTEST2PB,
  '__module__' : 'yb.util.proto_container_test2_pb2'
  # @@protoc_insertion_point(class_scope:yb.ProtoContainerTest2PB)
  })
_sym_db.RegisterMessage(ProtoContainerTest2PB)

TestObjectRequiredPB = _reflection.GeneratedProtocolMessageType('TestObjectRequiredPB', (_message.Message,), {
  'DESCRIPTOR' : _TESTOBJECTREQUIREDPB,
  '__module__' : 'yb.util.proto_container_test2_pb2'
  # @@protoc_insertion_point(class_scope:yb.TestObjectRequiredPB)
  })
_sym_db.RegisterMessage(TestObjectRequiredPB)

TestObjectRepeatedPB = _reflection.GeneratedProtocolMessageType('TestObjectRepeatedPB', (_message.Message,), {
  'DESCRIPTOR' : _TESTOBJECTREPEATEDPB,
  '__module__' : 'yb.util.proto_container_test2_pb2'
  # @@protoc_insertion_point(class_scope:yb.TestObjectRepeatedPB)
  })
_sym_db.RegisterMessage(TestObjectRepeatedPB)


# @@protoc_insertion_point(module_scope)
