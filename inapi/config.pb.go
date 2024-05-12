// Copyright 2015 Eryx <evorui аt gmаil dοt cοm>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v4.25.3
// source: config.proto

package inapi

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ConfigFieldType int32

const (
	ConfigFieldType_UnSpec             ConfigFieldType = 0
	ConfigFieldType_String             ConfigFieldType = 1
	ConfigFieldType_Select             ConfigFieldType = 2
	ConfigFieldType_Text               ConfigFieldType = 300
	ConfigFieldType_TextJSON           ConfigFieldType = 301
	ConfigFieldType_TextTOML           ConfigFieldType = 302
	ConfigFieldType_TextYAML           ConfigFieldType = 303
	ConfigFieldType_TextINI            ConfigFieldType = 304
	ConfigFieldType_TextJavaProperties ConfigFieldType = 305
	ConfigFieldType_TextMarkdown       ConfigFieldType = 306
	ConfigFieldType_AuthCert           ConfigFieldType = 900
)

// Enum value maps for ConfigFieldType.
var (
	ConfigFieldType_name = map[int32]string{
		0:   "UnSpec",
		1:   "String",
		2:   "Select",
		300: "Text",
		301: "TextJSON",
		302: "TextTOML",
		303: "TextYAML",
		304: "TextINI",
		305: "TextJavaProperties",
		306: "TextMarkdown",
		900: "AuthCert",
	}
	ConfigFieldType_value = map[string]int32{
		"UnSpec":             0,
		"String":             1,
		"Select":             2,
		"Text":               300,
		"TextJSON":           301,
		"TextTOML":           302,
		"TextYAML":           303,
		"TextINI":            304,
		"TextJavaProperties": 305,
		"TextMarkdown":       306,
		"AuthCert":           900,
	}
)

func (x ConfigFieldType) Enum() *ConfigFieldType {
	p := new(ConfigFieldType)
	*p = x
	return p
}

func (x ConfigFieldType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConfigFieldType) Descriptor() protoreflect.EnumDescriptor {
	return file_config_proto_enumTypes[0].Descriptor()
}

func (ConfigFieldType) Type() protoreflect.EnumType {
	return &file_config_proto_enumTypes[0]
}

func (x ConfigFieldType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConfigFieldType.Descriptor instead.
func (ConfigFieldType) EnumDescriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{0}
}

type ConfigFieldSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name         string                      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Type         ConfigFieldType             `protobuf:"varint,2,opt,name=type,proto3,enum=inapi.ConfigFieldType" json:"type,omitempty" toml:"type,omitempty"`
	Title        string                      `protobuf:"bytes,3,opt,name=title,proto3" json:"title,omitempty" toml:"title,omitempty"`
	Prompt       string                      `protobuf:"bytes,4,opt,name=prompt,proto3" json:"prompt,omitempty" toml:"prompt,omitempty"`
	DefaultValue string                      `protobuf:"bytes,5,opt,name=default_value,json=defaultValue,proto3" json:"default_value,omitempty" toml:"default_value,omitempty"`
	AutoFill     string                      `protobuf:"bytes,6,opt,name=auto_fill,json=autoFill,proto3" json:"auto_fill,omitempty" toml:"auto_fill,omitempty"`
	Attrs        uint64                      `protobuf:"varint,7,opt,name=attrs,proto3" json:"attrs,omitempty" toml:"attrs,omitempty"`
	Enums        []*ConfigFieldSpec_KeyValue `protobuf:"bytes,13,rep,name=enums,proto3" json:"enums,omitempty" toml:"enums,omitempty"`
	Validates    []*ConfigFieldSpec_Validate `protobuf:"bytes,14,rep,name=validates,proto3" json:"validates,omitempty" toml:"validates,omitempty"`
	Description  string                      `protobuf:"bytes,15,opt,name=description,proto3" json:"description,omitempty" toml:"description,omitempty"`
}

func (x *ConfigFieldSpec) Reset() {
	*x = ConfigFieldSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigFieldSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigFieldSpec) ProtoMessage() {}

func (x *ConfigFieldSpec) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigFieldSpec.ProtoReflect.Descriptor instead.
func (*ConfigFieldSpec) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{0}
}

func (x *ConfigFieldSpec) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ConfigFieldSpec) GetType() ConfigFieldType {
	if x != nil {
		return x.Type
	}
	return ConfigFieldType_UnSpec
}

func (x *ConfigFieldSpec) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *ConfigFieldSpec) GetPrompt() string {
	if x != nil {
		return x.Prompt
	}
	return ""
}

func (x *ConfigFieldSpec) GetDefaultValue() string {
	if x != nil {
		return x.DefaultValue
	}
	return ""
}

func (x *ConfigFieldSpec) GetAutoFill() string {
	if x != nil {
		return x.AutoFill
	}
	return ""
}

func (x *ConfigFieldSpec) GetAttrs() uint64 {
	if x != nil {
		return x.Attrs
	}
	return 0
}

func (x *ConfigFieldSpec) GetEnums() []*ConfigFieldSpec_KeyValue {
	if x != nil {
		return x.Enums
	}
	return nil
}

func (x *ConfigFieldSpec) GetValidates() []*ConfigFieldSpec_Validate {
	if x != nil {
		return x.Validates
	}
	return nil
}

func (x *ConfigFieldSpec) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type ConfigSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name    string             `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Version string             `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty" toml:"version,omitempty"`
	Fields  []*ConfigFieldSpec `protobuf:"bytes,3,rep,name=fields,proto3" json:"fields,omitempty" toml:"fields,omitempty"`
}

func (x *ConfigSpec) Reset() {
	*x = ConfigSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigSpec) ProtoMessage() {}

func (x *ConfigSpec) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigSpec.ProtoReflect.Descriptor instead.
func (*ConfigSpec) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{1}
}

func (x *ConfigSpec) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ConfigSpec) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *ConfigSpec) GetFields() []*ConfigFieldSpec {
	if x != nil {
		return x.Fields
	}
	return nil
}

type ConfigFieldValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string          `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Type  ConfigFieldType `protobuf:"varint,2,opt,name=type,proto3,enum=inapi.ConfigFieldType" json:"type,omitempty" toml:"type,omitempty"`
	Value string          `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty" toml:"value,omitempty"`
	Attrs uint64          `protobuf:"varint,7,opt,name=attrs,proto3" json:"attrs,omitempty" toml:"attrs,omitempty"`
}

func (x *ConfigFieldValue) Reset() {
	*x = ConfigFieldValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigFieldValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigFieldValue) ProtoMessage() {}

func (x *ConfigFieldValue) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigFieldValue.ProtoReflect.Descriptor instead.
func (*ConfigFieldValue) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{2}
}

func (x *ConfigFieldValue) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ConfigFieldValue) GetType() ConfigFieldType {
	if x != nil {
		return x.Type
	}
	return ConfigFieldType_UnSpec
}

func (x *ConfigFieldValue) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *ConfigFieldValue) GetAttrs() uint64 {
	if x != nil {
		return x.Attrs
	}
	return 0
}

type ConfigInstance struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name    string              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Version string              `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty" toml:"version,omitempty"`
	Fields  []*ConfigFieldValue `protobuf:"bytes,3,rep,name=fields,proto3" json:"fields,omitempty" toml:"fields,omitempty"`
	Created int64               `protobuf:"varint,4,opt,name=created,proto3" json:"created,omitempty" toml:"created,omitempty"`
	Updated int64               `protobuf:"varint,5,opt,name=updated,proto3" json:"updated,omitempty" toml:"updated,omitempty"`
}

func (x *ConfigInstance) Reset() {
	*x = ConfigInstance{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigInstance) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigInstance) ProtoMessage() {}

func (x *ConfigInstance) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigInstance.ProtoReflect.Descriptor instead.
func (*ConfigInstance) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{3}
}

func (x *ConfigInstance) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ConfigInstance) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *ConfigInstance) GetFields() []*ConfigFieldValue {
	if x != nil {
		return x.Fields
	}
	return nil
}

func (x *ConfigInstance) GetCreated() int64 {
	if x != nil {
		return x.Created
	}
	return 0
}

func (x *ConfigInstance) GetUpdated() int64 {
	if x != nil {
		return x.Updated
	}
	return 0
}

type ConfigFieldSpec_KeyValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty" toml:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty" toml:"value,omitempty"`
}

func (x *ConfigFieldSpec_KeyValue) Reset() {
	*x = ConfigFieldSpec_KeyValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigFieldSpec_KeyValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigFieldSpec_KeyValue) ProtoMessage() {}

func (x *ConfigFieldSpec_KeyValue) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigFieldSpec_KeyValue.ProtoReflect.Descriptor instead.
func (*ConfigFieldSpec_KeyValue) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ConfigFieldSpec_KeyValue) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *ConfigFieldSpec_KeyValue) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

type ConfigFieldSpec_Validate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Expr string `protobuf:"bytes,2,opt,name=expr,proto3" json:"expr,omitempty" toml:"expr,omitempty"`
	Hint string `protobuf:"bytes,3,opt,name=hint,proto3" json:"hint,omitempty" toml:"hint,omitempty"`
}

func (x *ConfigFieldSpec_Validate) Reset() {
	*x = ConfigFieldSpec_Validate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigFieldSpec_Validate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigFieldSpec_Validate) ProtoMessage() {}

func (x *ConfigFieldSpec_Validate) ProtoReflect() protoreflect.Message {
	mi := &file_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigFieldSpec_Validate.ProtoReflect.Descriptor instead.
func (*ConfigFieldSpec_Validate) Descriptor() ([]byte, []int) {
	return file_config_proto_rawDescGZIP(), []int{0, 1}
}

func (x *ConfigFieldSpec_Validate) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ConfigFieldSpec_Validate) GetExpr() string {
	if x != nil {
		return x.Expr
	}
	return ""
}

func (x *ConfigFieldSpec_Validate) GetHint() string {
	if x != nil {
		return x.Hint
	}
	return ""
}

var File_config_proto protoreflect.FileDescriptor

var file_config_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05,
	0x69, 0x6e, 0x61, 0x70, 0x69, 0x22, 0xeb, 0x03, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x46, 0x69, 0x65, 0x6c, 0x64, 0x53, 0x70, 0x65, 0x63, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x69, 0x6e,
	0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69, 0x74,
	0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x12,
	0x16, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x1b, 0x0a, 0x09,
	0x61, 0x75, 0x74, 0x6f, 0x5f, 0x66, 0x69, 0x6c, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x61, 0x75, 0x74, 0x6f, 0x46, 0x69, 0x6c, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x74, 0x74,
	0x72, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x12,
	0x35, 0x0a, 0x05, 0x65, 0x6e, 0x75, 0x6d, 0x73, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f,
	0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x65,
	0x6c, 0x64, 0x53, 0x70, 0x65, 0x63, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52,
	0x05, 0x65, 0x6e, 0x75, 0x6d, 0x73, 0x12, 0x3d, 0x0a, 0x09, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x73, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x69, 0x6e, 0x61, 0x70,
	0x69, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x53, 0x70, 0x65,
	0x63, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x52, 0x09, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x32, 0x0a, 0x08, 0x4b, 0x65, 0x79, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x46, 0x0a, 0x08, 0x56,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x65,
	0x78, 0x70, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x65, 0x78, 0x70, 0x72, 0x12,
	0x12, 0x0a, 0x04, 0x68, 0x69, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68,
	0x69, 0x6e, 0x74, 0x22, 0x6a, 0x0a, 0x0a, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x70, 0x65,
	0x63, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x2e, 0x0a, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x16, 0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x53, 0x70, 0x65, 0x63, 0x52, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x22,
	0x7e, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x74, 0x74,
	0x72, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x22,
	0xa3, 0x01, 0x0a, 0x0e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e,
	0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x2f, 0x0a, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46,
	0x69, 0x65, 0x6c, 0x64, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x73, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x75, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x2a, 0xb6, 0x01, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x46, 0x69, 0x65, 0x6c, 0x64, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x55, 0x6e, 0x53,
	0x70, 0x65, 0x63, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x10,
	0x01, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x10, 0x02, 0x12, 0x09, 0x0a,
	0x04, 0x54, 0x65, 0x78, 0x74, 0x10, 0xac, 0x02, 0x12, 0x0d, 0x0a, 0x08, 0x54, 0x65, 0x78, 0x74,
	0x4a, 0x53, 0x4f, 0x4e, 0x10, 0xad, 0x02, 0x12, 0x0d, 0x0a, 0x08, 0x54, 0x65, 0x78, 0x74, 0x54,
	0x4f, 0x4d, 0x4c, 0x10, 0xae, 0x02, 0x12, 0x0d, 0x0a, 0x08, 0x54, 0x65, 0x78, 0x74, 0x59, 0x41,
	0x4d, 0x4c, 0x10, 0xaf, 0x02, 0x12, 0x0c, 0x0a, 0x07, 0x54, 0x65, 0x78, 0x74, 0x49, 0x4e, 0x49,
	0x10, 0xb0, 0x02, 0x12, 0x17, 0x0a, 0x12, 0x54, 0x65, 0x78, 0x74, 0x4a, 0x61, 0x76, 0x61, 0x50,
	0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x10, 0xb1, 0x02, 0x12, 0x11, 0x0a, 0x0c,
	0x54, 0x65, 0x78, 0x74, 0x4d, 0x61, 0x72, 0x6b, 0x64, 0x6f, 0x77, 0x6e, 0x10, 0xb2, 0x02, 0x12,
	0x0d, 0x0a, 0x08, 0x41, 0x75, 0x74, 0x68, 0x43, 0x65, 0x72, 0x74, 0x10, 0x84, 0x07, 0x42, 0x0a,
	0x5a, 0x08, 0x2e, 0x2f, 0x3b, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_config_proto_rawDescOnce sync.Once
	file_config_proto_rawDescData = file_config_proto_rawDesc
)

func file_config_proto_rawDescGZIP() []byte {
	file_config_proto_rawDescOnce.Do(func() {
		file_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_proto_rawDescData)
	})
	return file_config_proto_rawDescData
}

var file_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_config_proto_goTypes = []interface{}{
	(ConfigFieldType)(0),             // 0: inapi.ConfigFieldType
	(*ConfigFieldSpec)(nil),          // 1: inapi.ConfigFieldSpec
	(*ConfigSpec)(nil),               // 2: inapi.ConfigSpec
	(*ConfigFieldValue)(nil),         // 3: inapi.ConfigFieldValue
	(*ConfigInstance)(nil),           // 4: inapi.ConfigInstance
	(*ConfigFieldSpec_KeyValue)(nil), // 5: inapi.ConfigFieldSpec.KeyValue
	(*ConfigFieldSpec_Validate)(nil), // 6: inapi.ConfigFieldSpec.Validate
}
var file_config_proto_depIdxs = []int32{
	0, // 0: inapi.ConfigFieldSpec.type:type_name -> inapi.ConfigFieldType
	5, // 1: inapi.ConfigFieldSpec.enums:type_name -> inapi.ConfigFieldSpec.KeyValue
	6, // 2: inapi.ConfigFieldSpec.validates:type_name -> inapi.ConfigFieldSpec.Validate
	1, // 3: inapi.ConfigSpec.fields:type_name -> inapi.ConfigFieldSpec
	0, // 4: inapi.ConfigFieldValue.type:type_name -> inapi.ConfigFieldType
	3, // 5: inapi.ConfigInstance.fields:type_name -> inapi.ConfigFieldValue
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_config_proto_init() }
func file_config_proto_init() {
	if File_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigFieldSpec); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigSpec); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigFieldValue); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigInstance); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigFieldSpec_KeyValue); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConfigFieldSpec_Validate); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_proto_goTypes,
		DependencyIndexes: file_config_proto_depIdxs,
		EnumInfos:         file_config_proto_enumTypes,
		MessageInfos:      file_config_proto_msgTypes,
	}.Build()
	File_config_proto = out.File
	file_config_proto_rawDesc = nil
	file_config_proto_goTypes = nil
	file_config_proto_depIdxs = nil
}
