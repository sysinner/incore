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
// 	protoc-gen-go v1.26.0-devel
// 	protoc        v3.16.0
// source: inapi.proto

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

type ErrorMeta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    string `protobuf:"bytes,1,opt,name=code,proto3" json:"code,omitempty" toml:"code,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty" toml:"message,omitempty"`
}

func (x *ErrorMeta) Reset() {
	*x = ErrorMeta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inapi_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ErrorMeta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ErrorMeta) ProtoMessage() {}

func (x *ErrorMeta) ProtoReflect() protoreflect.Message {
	mi := &file_inapi_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ErrorMeta.ProtoReflect.Descriptor instead.
func (*ErrorMeta) Descriptor() ([]byte, []int) {
	return file_inapi_proto_rawDescGZIP(), []int{0}
}

func (x *ErrorMeta) GetCode() string {
	if x != nil {
		return x.Code
	}
	return ""
}

func (x *ErrorMeta) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type TypeMeta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kind  string     `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty" toml:"kind,omitempty"`
	Error *ErrorMeta `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty" toml:"error,omitempty"`
}

func (x *TypeMeta) Reset() {
	*x = TypeMeta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inapi_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TypeMeta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TypeMeta) ProtoMessage() {}

func (x *TypeMeta) ProtoReflect() protoreflect.Message {
	mi := &file_inapi_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TypeMeta.ProtoReflect.Descriptor instead.
func (*TypeMeta) Descriptor() ([]byte, []int) {
	return file_inapi_proto_rawDescGZIP(), []int{1}
}

func (x *TypeMeta) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *TypeMeta) GetError() *ErrorMeta {
	if x != nil {
		return x.Error
	}
	return nil
}

type ObjectMeta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" toml:"id,omitempty"`
	Name    string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"`
	Created uint64 `protobuf:"varint,3,opt,name=created,proto3" json:"created,omitempty" toml:"created,omitempty"`
	Updated uint64 `protobuf:"varint,4,opt,name=updated,proto3" json:"updated,omitempty" toml:"updated,omitempty"`
}

func (x *ObjectMeta) Reset() {
	*x = ObjectMeta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inapi_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ObjectMeta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ObjectMeta) ProtoMessage() {}

func (x *ObjectMeta) ProtoReflect() protoreflect.Message {
	mi := &file_inapi_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ObjectMeta.ProtoReflect.Descriptor instead.
func (*ObjectMeta) Descriptor() ([]byte, []int) {
	return file_inapi_proto_rawDescGZIP(), []int{2}
}

func (x *ObjectMeta) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ObjectMeta) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ObjectMeta) GetCreated() uint64 {
	if x != nil {
		return x.Created
	}
	return 0
}

func (x *ObjectMeta) GetUpdated() uint64 {
	if x != nil {
		return x.Updated
	}
	return 0
}

type Label struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" toml:"name,omitempty"` // struct:object_slice_key
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty" toml:"value,omitempty"`
}

func (x *Label) Reset() {
	*x = Label{}
	if protoimpl.UnsafeEnabled {
		mi := &file_inapi_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Label) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Label) ProtoMessage() {}

func (x *Label) ProtoReflect() protoreflect.Message {
	mi := &file_inapi_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Label.ProtoReflect.Descriptor instead.
func (*Label) Descriptor() ([]byte, []int) {
	return file_inapi_proto_rawDescGZIP(), []int{3}
}

func (x *Label) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Label) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

var File_inapi_proto protoreflect.FileDescriptor

var file_inapi_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x69,
	0x6e, 0x61, 0x70, 0x69, 0x22, 0x39, 0x0a, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x4d, 0x65, 0x74,
	0x61, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22,
	0x46, 0x0a, 0x08, 0x54, 0x79, 0x70, 0x65, 0x4d, 0x65, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x6b,
	0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12,
	0x26, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10,
	0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x4d, 0x65, 0x74, 0x61,
	0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x64, 0x0a, 0x0a, 0x4f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x4d, 0x65, 0x74, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x22, 0x31, 0x0a,
	0x05, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x2f, 0x3b, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_inapi_proto_rawDescOnce sync.Once
	file_inapi_proto_rawDescData = file_inapi_proto_rawDesc
)

func file_inapi_proto_rawDescGZIP() []byte {
	file_inapi_proto_rawDescOnce.Do(func() {
		file_inapi_proto_rawDescData = protoimpl.X.CompressGZIP(file_inapi_proto_rawDescData)
	})
	return file_inapi_proto_rawDescData
}

var file_inapi_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_inapi_proto_goTypes = []interface{}{
	(*ErrorMeta)(nil),  // 0: inapi.ErrorMeta
	(*TypeMeta)(nil),   // 1: inapi.TypeMeta
	(*ObjectMeta)(nil), // 2: inapi.ObjectMeta
	(*Label)(nil),      // 3: inapi.Label
}
var file_inapi_proto_depIdxs = []int32{
	0, // 0: inapi.TypeMeta.error:type_name -> inapi.ErrorMeta
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_inapi_proto_init() }
func file_inapi_proto_init() {
	if File_inapi_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_inapi_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ErrorMeta); i {
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
		file_inapi_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TypeMeta); i {
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
		file_inapi_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ObjectMeta); i {
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
		file_inapi_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Label); i {
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
			RawDescriptor: file_inapi_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_inapi_proto_goTypes,
		DependencyIndexes: file_inapi_proto_depIdxs,
		MessageInfos:      file_inapi_proto_msgTypes,
	}.Build()
	File_inapi_proto = out.File
	file_inapi_proto_rawDesc = nil
	file_inapi_proto_goTypes = nil
	file_inapi_proto_depIdxs = nil
}
