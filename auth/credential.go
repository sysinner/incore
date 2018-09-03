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

package auth

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/status"
)

const (
	ns_auth_type              = "la"
	ns_auth_type_sha256       = "sha256"
	ns_auth_type_algdef       = ns_auth_type_sha256
	ns_auth_token             = "tk"
	ns_auth_client_id         = "c"
	ns_auth_reqtime           = "rt"
	auth_reqtime_range  int64 = 600
)

// type AuthInfo struct {
// }
//
// func (t AuthInfo) AuthType() string {
// 	return ns_auth_type
// }
//
// type TokenServer struct {
// }
//
// func NewCredentialServer() credentials.TransportCredentials {
// 	return TokenServer{}
// }
//
// func (s TokenServer) ClientHandshake(ctx context.Context, auth string, cn net.Conn) (net.Conn, credentials.AuthInfo, error) {
//
// 	fmt.Println("ClientHandshake", ctx, auth)
// 	return cn, AuthInfo{}, nil
// }
//
// func (s TokenServer) ServerHandshake(cn net.Conn) (net.Conn, credentials.AuthInfo, error) {
// 	fmt.Println("ServerHandshake")
// 	return cn, AuthInfo{}, nil
// }
//
// func (s TokenServer) Info() credentials.ProtocolInfo {
// 	fmt.Println("Info")
// 	return credentials.ProtocolInfo{}
// }
//
// func (s TokenServer) Clone() credentials.TransportCredentials {
// 	fmt.Println("Clone")
// 	return s
// }
//
// func (s TokenServer) OverrideServerName(name string) error {
// 	fmt.Println("OverrideServerName")
// 	return nil
// }

func TokenValid(ctx context.Context) error {

	md, ok := metadata.FromContext(ctx)
	if !ok || len(md) < 4 {
		return grpc.Errorf(codes.Unauthenticated, "No AuthToken Found")
	}

	//
	t, ok := md[ns_auth_type]
	if !ok || len(t) == 0 {
		return grpc.Errorf(codes.Unauthenticated, "No AuthType Found")
	}

	//
	client_id, ok := md[ns_auth_client_id]
	if !ok || len(client_id) == 0 {
		return grpc.Errorf(codes.Unauthenticated, "No Client Id Found")
	}

	//
	key := status.ZoneHostSecretKeys.Get(client_id[0])
	if key == nil || len(key) == 0 {
		return grpc.Errorf(codes.Unauthenticated, "No SecretKey Found (client:"+client_id[0]+")")
	}

	//
	rt, ok := md[ns_auth_reqtime]
	if !ok || len(rt) == 0 {
		return grpc.Errorf(codes.Unauthenticated, "No rt Found")
	}
	rti, err := strconv.ParseInt(rt[0], 10, 64)
	if err != nil || rti < 1000000000 {
		return grpc.Errorf(codes.Unauthenticated, "Invalid Request Time")
	}
	rtli := time.Now().UTC().Unix()
	if pos := rtli - rti; pos < -auth_reqtime_range || pos > auth_reqtime_range {
		return grpc.Errorf(codes.Unauthenticated, "Invalid Request Time")
	}

	//
	tk, ok := md[ns_auth_token]
	if !ok || len(tk) == 0 {
		return grpc.Errorf(codes.Unauthenticated, "No token Found")
	}

	// {
	// 	t_start := time.Now()
	// 	token_encode(t[0], client_id[0], rt[0], key.String())
	// 	fmt.Println("token_encode in", time.Since(t_start))
	// }

	//
	if tk[0] != token_encode(t[0], client_id[0], rt[0], key.String()) {
		return grpc.Errorf(codes.Unauthenticated, "Invalid Token")
	}

	return nil
}

type TokenSource struct {
}

func NewCredentialToken() credentials.PerRPCCredentials {
	return TokenSource{}
}

func (s TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {

	rt := time_request()

	return map[string]string{
		ns_auth_type:      ns_auth_type_algdef,
		ns_auth_client_id: config.Config.Host.Id,
		ns_auth_reqtime:   rt,
		ns_auth_token: token_encode(
			ns_auth_type_algdef,
			status.Host.Meta.Id,
			rt,
			config.Config.Host.SecretKey,
		),
	}, nil
}

func (s TokenSource) RequireTransportSecurity() bool {
	return false
}

func time_request() string {
	return strconv.FormatInt(time.Now().UTC().Unix(), 10)
}

func token_encode(t, client_id, rtime, key string) (rs string) {

	switch t {

	case ns_auth_type_sha256:
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s.%s.%s", client_id, rtime, key)))
		rs = fmt.Sprintf("%x", h.Sum(nil))

	default:
		rs = "<nil>"
	}

	return
}
