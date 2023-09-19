# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: yb/util/encryption.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='yb/util/encryption.proto',
  package='yb',
  syntax='proto3',
  serialized_options=b'\n\006org.yb',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x18yb/util/encryption.proto\x12\x02yb\"s\n\x12\x45ncryptionParamsPB\x12\x10\n\x08\x64\x61ta_key\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\x12\x0f\n\x07\x63ounter\x18\x03 \x01(\x05\x12+\n#openssl_compatible_counter_overflow\x18\x04 \x01(\x08\"f\n\x0eUniverseKeysPB\x12(\n\x03map\x18\x01 \x03(\x0b\x32\x1b.yb.UniverseKeysPB.MapEntry\x1a*\n\x08MapEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\"\xdf\x01\n\x15UniverseKeyRegistryPB\x12\x1a\n\x12\x65ncryption_enabled\x18\x01 \x01(\x08\x12\x42\n\runiverse_keys\x18\x02 \x03(\x0b\x32+.yb.UniverseKeyRegistryPB.UniverseKeysEntry\x12\x19\n\x11latest_version_id\x18\x03 \x01(\t\x1aK\n\x11UniverseKeysEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.yb.EncryptionParamsPB:\x02\x38\x01\x42\x08\n\x06org.ybb\x06proto3'
)




_ENCRYPTIONPARAMSPB = _descriptor.Descriptor(
  name='EncryptionParamsPB',
  full_name='yb.EncryptionParamsPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='data_key', full_name='yb.EncryptionParamsPB.data_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='yb.EncryptionParamsPB.nonce', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='counter', full_name='yb.EncryptionParamsPB.counter', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='openssl_compatible_counter_overflow', full_name='yb.EncryptionParamsPB.openssl_compatible_counter_overflow', index=3,
      number=4, type=8, cpp_type=7, label=1,
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=32,
  serialized_end=147,
)


_UNIVERSEKEYSPB_MAPENTRY = _descriptor.Descriptor(
  name='MapEntry',
  full_name='yb.UniverseKeysPB.MapEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='yb.UniverseKeysPB.MapEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='yb.UniverseKeysPB.MapEntry.value', index=1,
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
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=209,
  serialized_end=251,
)

_UNIVERSEKEYSPB = _descriptor.Descriptor(
  name='UniverseKeysPB',
  full_name='yb.UniverseKeysPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='map', full_name='yb.UniverseKeysPB.map', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_UNIVERSEKEYSPB_MAPENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=149,
  serialized_end=251,
)


_UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY = _descriptor.Descriptor(
  name='UniverseKeysEntry',
  full_name='yb.UniverseKeyRegistryPB.UniverseKeysEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='yb.UniverseKeyRegistryPB.UniverseKeysEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='yb.UniverseKeyRegistryPB.UniverseKeysEntry.value', index=1,
      number=2, type=11, cpp_type=10, label=1,
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
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=402,
  serialized_end=477,
)

_UNIVERSEKEYREGISTRYPB = _descriptor.Descriptor(
  name='UniverseKeyRegistryPB',
  full_name='yb.UniverseKeyRegistryPB',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='encryption_enabled', full_name='yb.UniverseKeyRegistryPB.encryption_enabled', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='universe_keys', full_name='yb.UniverseKeyRegistryPB.universe_keys', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='latest_version_id', full_name='yb.UniverseKeyRegistryPB.latest_version_id', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=254,
  serialized_end=477,
)

_UNIVERSEKEYSPB_MAPENTRY.containing_type = _UNIVERSEKEYSPB
_UNIVERSEKEYSPB.fields_by_name['map'].message_type = _UNIVERSEKEYSPB_MAPENTRY
_UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY.fields_by_name['value'].message_type = _ENCRYPTIONPARAMSPB
_UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY.containing_type = _UNIVERSEKEYREGISTRYPB
_UNIVERSEKEYREGISTRYPB.fields_by_name['universe_keys'].message_type = _UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY
DESCRIPTOR.message_types_by_name['EncryptionParamsPB'] = _ENCRYPTIONPARAMSPB
DESCRIPTOR.message_types_by_name['UniverseKeysPB'] = _UNIVERSEKEYSPB
DESCRIPTOR.message_types_by_name['UniverseKeyRegistryPB'] = _UNIVERSEKEYREGISTRYPB
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

EncryptionParamsPB = _reflection.GeneratedProtocolMessageType('EncryptionParamsPB', (_message.Message,), {
  'DESCRIPTOR' : _ENCRYPTIONPARAMSPB,
  '__module__' : 'yb.util.encryption_pb2'
  # @@protoc_insertion_point(class_scope:yb.EncryptionParamsPB)
  })
_sym_db.RegisterMessage(EncryptionParamsPB)

UniverseKeysPB = _reflection.GeneratedProtocolMessageType('UniverseKeysPB', (_message.Message,), {

  'MapEntry' : _reflection.GeneratedProtocolMessageType('MapEntry', (_message.Message,), {
    'DESCRIPTOR' : _UNIVERSEKEYSPB_MAPENTRY,
    '__module__' : 'yb.util.encryption_pb2'
    # @@protoc_insertion_point(class_scope:yb.UniverseKeysPB.MapEntry)
    })
  ,
  'DESCRIPTOR' : _UNIVERSEKEYSPB,
  '__module__' : 'yb.util.encryption_pb2'
  # @@protoc_insertion_point(class_scope:yb.UniverseKeysPB)
  })
_sym_db.RegisterMessage(UniverseKeysPB)
_sym_db.RegisterMessage(UniverseKeysPB.MapEntry)

UniverseKeyRegistryPB = _reflection.GeneratedProtocolMessageType('UniverseKeyRegistryPB', (_message.Message,), {

  'UniverseKeysEntry' : _reflection.GeneratedProtocolMessageType('UniverseKeysEntry', (_message.Message,), {
    'DESCRIPTOR' : _UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY,
    '__module__' : 'yb.util.encryption_pb2'
    # @@protoc_insertion_point(class_scope:yb.UniverseKeyRegistryPB.UniverseKeysEntry)
    })
  ,
  'DESCRIPTOR' : _UNIVERSEKEYREGISTRYPB,
  '__module__' : 'yb.util.encryption_pb2'
  # @@protoc_insertion_point(class_scope:yb.UniverseKeyRegistryPB)
  })
_sym_db.RegisterMessage(UniverseKeyRegistryPB)
_sym_db.RegisterMessage(UniverseKeyRegistryPB.UniverseKeysEntry)


DESCRIPTOR._options = None
_UNIVERSEKEYSPB_MAPENTRY._options = None
_UNIVERSEKEYREGISTRYPB_UNIVERSEKEYSENTRY._options = None
# @@protoc_insertion_point(module_scope)
