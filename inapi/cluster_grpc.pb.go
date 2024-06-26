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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.3
// source: cluster.proto

package inapi

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ApiHostMember_HostJoin_FullMethodName = "/inapi.ApiHostMember/HostJoin"
)

// ApiHostMemberClient is the client API for ApiHostMember service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ApiHostMemberClient interface {
	HostJoin(ctx context.Context, in *ResHostNew, opts ...grpc.CallOption) (*ResHost, error)
}

type apiHostMemberClient struct {
	cc grpc.ClientConnInterface
}

func NewApiHostMemberClient(cc grpc.ClientConnInterface) ApiHostMemberClient {
	return &apiHostMemberClient{cc}
}

func (c *apiHostMemberClient) HostJoin(ctx context.Context, in *ResHostNew, opts ...grpc.CallOption) (*ResHost, error) {
	out := new(ResHost)
	err := c.cc.Invoke(ctx, ApiHostMember_HostJoin_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ApiHostMemberServer is the server API for ApiHostMember service.
// All implementations must embed UnimplementedApiHostMemberServer
// for forward compatibility
type ApiHostMemberServer interface {
	HostJoin(context.Context, *ResHostNew) (*ResHost, error)
	mustEmbedUnimplementedApiHostMemberServer()
}

// UnimplementedApiHostMemberServer must be embedded to have forward compatible implementations.
type UnimplementedApiHostMemberServer struct {
}

func (UnimplementedApiHostMemberServer) HostJoin(context.Context, *ResHostNew) (*ResHost, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HostJoin not implemented")
}
func (UnimplementedApiHostMemberServer) mustEmbedUnimplementedApiHostMemberServer() {}

// UnsafeApiHostMemberServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ApiHostMemberServer will
// result in compilation errors.
type UnsafeApiHostMemberServer interface {
	mustEmbedUnimplementedApiHostMemberServer()
}

func RegisterApiHostMemberServer(s grpc.ServiceRegistrar, srv ApiHostMemberServer) {
	s.RegisterService(&ApiHostMember_ServiceDesc, srv)
}

func _ApiHostMember_HostJoin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResHostNew)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ApiHostMemberServer).HostJoin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ApiHostMember_HostJoin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ApiHostMemberServer).HostJoin(ctx, req.(*ResHostNew))
	}
	return interceptor(ctx, in, info, handler)
}

// ApiHostMember_ServiceDesc is the grpc.ServiceDesc for ApiHostMember service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ApiHostMember_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "inapi.ApiHostMember",
	HandlerType: (*ApiHostMemberServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HostJoin",
			Handler:    _ApiHostMember_HostJoin_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cluster.proto",
}

const (
	ApiZoneMaster_HostConfig_FullMethodName     = "/inapi.ApiZoneMaster/HostConfig"
	ApiZoneMaster_HostStatusSync_FullMethodName = "/inapi.ApiZoneMaster/HostStatusSync"
)

// ApiZoneMasterClient is the client API for ApiZoneMaster service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ApiZoneMasterClient interface {
	HostConfig(ctx context.Context, in *ZoneHostConfigRequest, opts ...grpc.CallOption) (*ZoneHostConfigReply, error)
	HostStatusSync(ctx context.Context, in *ResHost, opts ...grpc.CallOption) (*ResHostBound, error)
}

type apiZoneMasterClient struct {
	cc grpc.ClientConnInterface
}

func NewApiZoneMasterClient(cc grpc.ClientConnInterface) ApiZoneMasterClient {
	return &apiZoneMasterClient{cc}
}

func (c *apiZoneMasterClient) HostConfig(ctx context.Context, in *ZoneHostConfigRequest, opts ...grpc.CallOption) (*ZoneHostConfigReply, error) {
	out := new(ZoneHostConfigReply)
	err := c.cc.Invoke(ctx, ApiZoneMaster_HostConfig_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *apiZoneMasterClient) HostStatusSync(ctx context.Context, in *ResHost, opts ...grpc.CallOption) (*ResHostBound, error) {
	out := new(ResHostBound)
	err := c.cc.Invoke(ctx, ApiZoneMaster_HostStatusSync_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ApiZoneMasterServer is the server API for ApiZoneMaster service.
// All implementations must embed UnimplementedApiZoneMasterServer
// for forward compatibility
type ApiZoneMasterServer interface {
	HostConfig(context.Context, *ZoneHostConfigRequest) (*ZoneHostConfigReply, error)
	HostStatusSync(context.Context, *ResHost) (*ResHostBound, error)
	mustEmbedUnimplementedApiZoneMasterServer()
}

// UnimplementedApiZoneMasterServer must be embedded to have forward compatible implementations.
type UnimplementedApiZoneMasterServer struct {
}

func (UnimplementedApiZoneMasterServer) HostConfig(context.Context, *ZoneHostConfigRequest) (*ZoneHostConfigReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HostConfig not implemented")
}
func (UnimplementedApiZoneMasterServer) HostStatusSync(context.Context, *ResHost) (*ResHostBound, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HostStatusSync not implemented")
}
func (UnimplementedApiZoneMasterServer) mustEmbedUnimplementedApiZoneMasterServer() {}

// UnsafeApiZoneMasterServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ApiZoneMasterServer will
// result in compilation errors.
type UnsafeApiZoneMasterServer interface {
	mustEmbedUnimplementedApiZoneMasterServer()
}

func RegisterApiZoneMasterServer(s grpc.ServiceRegistrar, srv ApiZoneMasterServer) {
	s.RegisterService(&ApiZoneMaster_ServiceDesc, srv)
}

func _ApiZoneMaster_HostConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ZoneHostConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ApiZoneMasterServer).HostConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ApiZoneMaster_HostConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ApiZoneMasterServer).HostConfig(ctx, req.(*ZoneHostConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ApiZoneMaster_HostStatusSync_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResHost)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ApiZoneMasterServer).HostStatusSync(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ApiZoneMaster_HostStatusSync_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ApiZoneMasterServer).HostStatusSync(ctx, req.(*ResHost))
	}
	return interceptor(ctx, in, info, handler)
}

// ApiZoneMaster_ServiceDesc is the grpc.ServiceDesc for ApiZoneMaster service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ApiZoneMaster_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "inapi.ApiZoneMaster",
	HandlerType: (*ApiZoneMasterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HostConfig",
			Handler:    _ApiZoneMaster_HostConfig_Handler,
		},
		{
			MethodName: "HostStatusSync",
			Handler:    _ApiZoneMaster_HostStatusSync_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cluster.proto",
}
