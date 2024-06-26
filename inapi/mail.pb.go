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
// source: mail.proto

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

type MailPodStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string               `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" toml:"id,omitempty"`
	User    string               `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty" toml:"user,omitempty"`
	Items   []*MailPodStatus_Pod `protobuf:"bytes,3,rep,name=items,proto3" json:"items,omitempty" toml:"items,omitempty"`
	Created uint32               `protobuf:"varint,5,opt,name=created,proto3" json:"created,omitempty" toml:"created,omitempty"`
	WeekNum uint32               `protobuf:"varint,6,opt,name=week_num,json=weekNum,proto3" json:"week_num,omitempty" toml:"week_num,omitempty"`
}

func (x *MailPodStatus) Reset() {
	*x = MailPodStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mail_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MailPodStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MailPodStatus) ProtoMessage() {}

func (x *MailPodStatus) ProtoReflect() protoreflect.Message {
	mi := &file_mail_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MailPodStatus.ProtoReflect.Descriptor instead.
func (*MailPodStatus) Descriptor() ([]byte, []int) {
	return file_mail_proto_rawDescGZIP(), []int{0}
}

func (x *MailPodStatus) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *MailPodStatus) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *MailPodStatus) GetItems() []*MailPodStatus_Pod {
	if x != nil {
		return x.Items
	}
	return nil
}

func (x *MailPodStatus) GetCreated() uint32 {
	if x != nil {
		return x.Created
	}
	return 0
}

func (x *MailPodStatus) GetWeekNum() uint32 {
	if x != nil {
		return x.WeekNum
	}
	return 0
}

type MailPodStatus_PodReplica struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" toml:"id,omitempty"`
	VolUsed int64  `protobuf:"varint,2,opt,name=vol_used,json=volUsed,proto3" json:"vol_used,omitempty" toml:"vol_used,omitempty"`
}

func (x *MailPodStatus_PodReplica) Reset() {
	*x = MailPodStatus_PodReplica{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mail_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MailPodStatus_PodReplica) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MailPodStatus_PodReplica) ProtoMessage() {}

func (x *MailPodStatus_PodReplica) ProtoReflect() protoreflect.Message {
	mi := &file_mail_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MailPodStatus_PodReplica.ProtoReflect.Descriptor instead.
func (*MailPodStatus_PodReplica) Descriptor() ([]byte, []int) {
	return file_mail_proto_rawDescGZIP(), []int{0, 0}
}

func (x *MailPodStatus_PodReplica) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *MailPodStatus_PodReplica) GetVolUsed() int64 {
	if x != nil {
		return x.VolUsed
	}
	return 0
}

type MailPodStatus_Pod struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PodId              string                      `protobuf:"bytes,1,opt,name=pod_id,json=podId,proto3" json:"pod_id,omitempty" toml:"pod_id,omitempty"`
	PodName            string                      `protobuf:"bytes,9,opt,name=pod_name,json=podName,proto3" json:"pod_name,omitempty" toml:"pod_name,omitempty"`
	ZoneName           string                      `protobuf:"bytes,2,opt,name=zone_name,json=zoneName,proto3" json:"zone_name,omitempty" toml:"zone_name,omitempty"`
	CellName           string                      `protobuf:"bytes,3,opt,name=cell_name,json=cellName,proto3" json:"cell_name,omitempty" toml:"cell_name,omitempty"`
	SpecCpu            int32                       `protobuf:"varint,5,opt,name=spec_cpu,json=specCpu,proto3" json:"spec_cpu,omitempty" toml:"spec_cpu,omitempty"`
	SpecMem            int32                       `protobuf:"varint,6,opt,name=spec_mem,json=specMem,proto3" json:"spec_mem,omitempty" toml:"spec_mem,omitempty"`
	SpecVol            int32                       `protobuf:"varint,7,opt,name=spec_vol,json=specVol,proto3" json:"spec_vol,omitempty" toml:"spec_vol,omitempty"`
	PaymentCycleAmount float32                     `protobuf:"fixed32,8,opt,name=payment_cycle_amount,json=paymentCycleAmount,proto3" json:"payment_cycle_amount,omitempty" toml:"payment_cycle_amount,omitempty"`
	Reps               []*MailPodStatus_PodReplica `protobuf:"bytes,15,rep,name=reps,proto3" json:"reps,omitempty" toml:"reps,omitempty"`
}

func (x *MailPodStatus_Pod) Reset() {
	*x = MailPodStatus_Pod{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mail_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MailPodStatus_Pod) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MailPodStatus_Pod) ProtoMessage() {}

func (x *MailPodStatus_Pod) ProtoReflect() protoreflect.Message {
	mi := &file_mail_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MailPodStatus_Pod.ProtoReflect.Descriptor instead.
func (*MailPodStatus_Pod) Descriptor() ([]byte, []int) {
	return file_mail_proto_rawDescGZIP(), []int{0, 1}
}

func (x *MailPodStatus_Pod) GetPodId() string {
	if x != nil {
		return x.PodId
	}
	return ""
}

func (x *MailPodStatus_Pod) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

func (x *MailPodStatus_Pod) GetZoneName() string {
	if x != nil {
		return x.ZoneName
	}
	return ""
}

func (x *MailPodStatus_Pod) GetCellName() string {
	if x != nil {
		return x.CellName
	}
	return ""
}

func (x *MailPodStatus_Pod) GetSpecCpu() int32 {
	if x != nil {
		return x.SpecCpu
	}
	return 0
}

func (x *MailPodStatus_Pod) GetSpecMem() int32 {
	if x != nil {
		return x.SpecMem
	}
	return 0
}

func (x *MailPodStatus_Pod) GetSpecVol() int32 {
	if x != nil {
		return x.SpecVol
	}
	return 0
}

func (x *MailPodStatus_Pod) GetPaymentCycleAmount() float32 {
	if x != nil {
		return x.PaymentCycleAmount
	}
	return 0
}

func (x *MailPodStatus_Pod) GetReps() []*MailPodStatus_PodReplica {
	if x != nil {
		return x.Reps
	}
	return nil
}

var File_mail_proto protoreflect.FileDescriptor

var file_mail_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x69, 0x6e,
	0x61, 0x70, 0x69, 0x22, 0xfd, 0x03, 0x0a, 0x0d, 0x4d, 0x61, 0x69, 0x6c, 0x50, 0x6f, 0x64, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x05, 0x69, 0x74, 0x65,
	0x6d, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x69, 0x6e, 0x61, 0x70, 0x69,
	0x2e, 0x4d, 0x61, 0x69, 0x6c, 0x50, 0x6f, 0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x50,
	0x6f, 0x64, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x77, 0x65, 0x65, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x77, 0x65, 0x65, 0x6b, 0x4e, 0x75, 0x6d, 0x1a, 0x37,
	0x0a, 0x0a, 0x50, 0x6f, 0x64, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x19, 0x0a, 0x08,
	0x76, 0x6f, 0x6c, 0x5f, 0x75, 0x73, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07,
	0x76, 0x6f, 0x6c, 0x55, 0x73, 0x65, 0x64, 0x1a, 0xa9, 0x02, 0x0a, 0x03, 0x50, 0x6f, 0x64, 0x12,
	0x15, 0x0a, 0x06, 0x70, 0x6f, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x70, 0x6f, 0x64, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x6f, 0x64, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x6f, 0x64, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x1b, 0x0a, 0x09, 0x7a, 0x6f, 0x6e, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x7a, 0x6f, 0x6e, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x63, 0x65, 0x6c, 0x6c, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x63, 0x65, 0x6c, 0x6c, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x73,
	0x70, 0x65, 0x63, 0x5f, 0x63, 0x70, 0x75, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x73,
	0x70, 0x65, 0x63, 0x43, 0x70, 0x75, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x70, 0x65, 0x63, 0x5f, 0x6d,
	0x65, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x73, 0x70, 0x65, 0x63, 0x4d, 0x65,
	0x6d, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x70, 0x65, 0x63, 0x5f, 0x76, 0x6f, 0x6c, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x07, 0x73, 0x70, 0x65, 0x63, 0x56, 0x6f, 0x6c, 0x12, 0x30, 0x0a, 0x14,
	0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x79, 0x63, 0x6c, 0x65, 0x5f, 0x61, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x02, 0x52, 0x12, 0x70, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x43, 0x79, 0x63, 0x6c, 0x65, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x33,
	0x0a, 0x04, 0x72, 0x65, 0x70, 0x73, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x69,
	0x6e, 0x61, 0x70, 0x69, 0x2e, 0x4d, 0x61, 0x69, 0x6c, 0x50, 0x6f, 0x64, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2e, 0x50, 0x6f, 0x64, 0x52, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x52, 0x04, 0x72,
	0x65, 0x70, 0x73, 0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x2f, 0x3b, 0x69, 0x6e, 0x61, 0x70, 0x69, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_mail_proto_rawDescOnce sync.Once
	file_mail_proto_rawDescData = file_mail_proto_rawDesc
)

func file_mail_proto_rawDescGZIP() []byte {
	file_mail_proto_rawDescOnce.Do(func() {
		file_mail_proto_rawDescData = protoimpl.X.CompressGZIP(file_mail_proto_rawDescData)
	})
	return file_mail_proto_rawDescData
}

var file_mail_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_mail_proto_goTypes = []interface{}{
	(*MailPodStatus)(nil),            // 0: inapi.MailPodStatus
	(*MailPodStatus_PodReplica)(nil), // 1: inapi.MailPodStatus.PodReplica
	(*MailPodStatus_Pod)(nil),        // 2: inapi.MailPodStatus.Pod
}
var file_mail_proto_depIdxs = []int32{
	2, // 0: inapi.MailPodStatus.items:type_name -> inapi.MailPodStatus.Pod
	1, // 1: inapi.MailPodStatus.Pod.reps:type_name -> inapi.MailPodStatus.PodReplica
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_mail_proto_init() }
func file_mail_proto_init() {
	if File_mail_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_mail_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MailPodStatus); i {
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
		file_mail_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MailPodStatus_PodReplica); i {
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
		file_mail_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MailPodStatus_Pod); i {
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
			RawDescriptor: file_mail_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_mail_proto_goTypes,
		DependencyIndexes: file_mail_proto_depIdxs,
		MessageInfos:      file_mail_proto_msgTypes,
	}.Build()
	File_mail_proto = out.File
	file_mail_proto_rawDesc = nil
	file_mail_proto_goTypes = nil
	file_mail_proto_depIdxs = nil
}
