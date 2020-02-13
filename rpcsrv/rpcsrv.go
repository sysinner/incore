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

package rpcsrv

import (
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc"

	"github.com/sysinner/incore/auth"
)

var (
	// Server         = grpc.NewServer(grpc.Creds(NewCredentialServer()))
	grpcMsgByteMax = 16 * 1024 * 1024
	Server         = grpc.NewServer(
		grpc.MaxMsgSize(grpcMsgByteMax),
		grpc.MaxSendMsgSize(grpcMsgByteMax),
		grpc.MaxRecvMsgSize(grpcMsgByteMax),
	)
	clientConns  = map[string]*grpc.ClientConn{}
	clientConnMu sync.Mutex
)

func Start(port uint16) error {

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	go Server.Serve(lis)
	return nil
}

func ClientConn(addr string) (*grpc.ClientConn, error) {

	clientConnMu.Lock()
	defer clientConnMu.Unlock()

	if c, ok := clientConns[addr]; ok {
		return c, nil
	}

	c, err := grpc.Dial(addr, grpc.WithInsecure(),
		grpc.WithPerRPCCredentials(auth.NewCredentialToken()),
		grpc.WithMaxMsgSize(grpcMsgByteMax),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(grpcMsgByteMax)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(grpcMsgByteMax)),
	)
	if err != nil {
		return nil, err
	}

	clientConns[addr] = c

	return c, nil
}
