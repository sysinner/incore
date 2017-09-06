// Copyright 2015 Authors, All rights reserved.
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

	"github.com/lessos/loscore/auth"
)

var (
	// Server         = grpc.NewServer(grpc.Creds(NewCredentialServer()))
	Server         = grpc.NewServer()
	client_conns   = map[string]*grpc.ClientConn{}
	client_conn_mu sync.Mutex
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

	client_conn_mu.Lock()
	defer client_conn_mu.Unlock()

	if c, ok := client_conns[addr]; ok {
		return c, nil
	}

	c, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithPerRPCCredentials(auth.NewCredentialToken()))
	if err != nil {
		return nil, err
	}

	client_conns[addr] = c

	return c, nil
}
