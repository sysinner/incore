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

package o1

import (
	"context"
	"regexp"

	"github.com/hooto/httpsrv"

	iamdb "github.com/hooto/iam/data"
	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inrpc"
)

type Config struct {
	*httpsrv.Controller
}

func (c Config) HostJoinAction() {

	var (
		req incfg.HostJoinRequest
		rep inapi.WebServiceReply
	)
	defer c.RenderJson(&rep)

	//
	if len(incfg.Config.Zone.MainNodes) > 0 {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "the host only to perform a one-time initialization"
		return
	}

	//
	if err := c.Request.JsonDecode(&req); err != nil {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, err.Error()
		return
	}

	addr := inapi.HostNodeAddress(req.ZoneAddr)
	if addr.Port() == 0 {
		addr.SetPort(9529)
	}
	if !addr.Valid() {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "invalid zone address"
		return
	}
	req.ZoneAddr = addr.String()

	addr = inapi.HostNodeAddress(req.HostAddr)
	if addr.Port() == 0 {
		addr.SetPort(9529)
	}
	if !addr.Valid() {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "invalid host address"
		return
	}
	req.HostAddr = addr.String()

	req.HostId = incfg.Config.Host.Id
	req.HostSecretKey = incfg.Config.Host.SecretKey

	//
	conn, err := inrpc.ClientConn(req.ZoneAddr)
	if err != nil {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "Invalid Zone Address "+req.ZoneAddr
		return
	}

	rpcReq := &inapi.ZoneHostConfigRequest{
		Id:        req.HostId,
		CellId:    req.CellId,
		LanAddr:   req.HostAddr,
		SecretKey: incfg.Config.Host.SecretKey,
	}

	rs, err := inapi.NewApiZoneMasterClient(conn).HostConfig(
		context.Background(), rpcReq)
	if err != nil {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, err.Error()
		return
	}

	if len(rs.ZoneMainNodes) == 0 {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "server error"
		return
	}

	incfg.Config.Host.ZoneId = rs.ZoneId
	incfg.Config.Host.CellId = rs.CellId
	incfg.Config.Host.LanAddr = req.HostAddr
	incfg.Config.Host.WanAddr = req.HostAddr

	incfg.Config.Zone.ZoneId = rs.ZoneId
	incfg.Config.Zone.MainNodes = rs.ZoneMainNodes

	if err := incfg.Config.Flush(); err != nil {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, err.Error()
		return
	}

	rep.Kind = "OK"
}

func (c Config) ZoneInitAction() {

	var (
		req incfg.ZoneInitRequest
		rep inapi.WebServiceReply
	)
	defer c.RenderJson(&rep)

	//
	if err := c.Request.JsonDecode(&req); err != nil {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, err.Error()
		return
	}

	//
	if len(incfg.Config.Zone.MainNodes) > 0 {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "the cluster only to perform a one-time initialization"
		return
	}

	addr := inapi.HostNodeAddress(req.HostAddr)
	if addr.Port() == 0 {
		addr.SetPort(9529)
	}
	if !addr.Valid() {
		rep.Kind, rep.Message = inapi.ErrCodeClientError, "invalid host address"
		return
	}
	incfg.Config.Host.LanAddr = addr.String()

	incfg.Config.Zone.MainNodes = []string{
		incfg.Config.Host.LanAddr,
	}

	if req.HttpPort > 0 {
		if req.HttpPort == addr.Port() {
			rep.Kind, rep.Message = inapi.ErrCodeClientError, "http_port cannot be the same as host_addr(port)"
			return
		}
		incfg.Config.Zone.HttpPort = req.HttpPort
	} else {
		incfg.Config.Zone.HttpPort = 9530
	}

	{
		waddr := inapi.HostNodeAddress(req.WanAddr)
		if len(waddr) > 0 {
			if waddr.Port() == 0 {
				waddr.SetPort(1234)
			}
			if !waddr.Valid() {
				rep.Kind, rep.Message = inapi.ErrCodeClientError, "invalid WAN address"
				return
			}

			incfg.Config.Host.WanAddr = waddr.IP()
		}
	}

	//
	var ok bool
	var validCheck = func(name, val, def string, re *regexp.Regexp) (string, bool) {

		if val != "" {

			if !re.MatchString(val) {
				rep.Kind, rep.Message = inapi.ErrCodeClientError, "invalid "+name
				return "", false
			}

		} else {
			val = def
		}

		return val, true
	}

	if incfg.Config.Host.ZoneId, ok = validCheck("zone_id", req.ZoneId, "z1", inapi.ResSysZoneIdReg); !ok {
		return
	}

	if incfg.Config.Host.CellId, ok = validCheck("cell_id", req.CellId, "g1", inapi.ResSysCellIdReg); !ok {
		return
	}

	incfg.Config.Zone.ZoneId = incfg.Config.Host.ZoneId

	if incfg.Config.ZoneMain == nil {
		incfg.Config.ZoneMain = &incfg.ZoneMainConfig{}
	}

	if req.Password != "" {
		iamdb.DefaultSysadminPassword = req.Password
	}

	incfg.Config.ZoneMain.MultiHostEnable = true
	incfg.Config.ZoneMain.MultiCellEnable = true
	incfg.Config.ZoneMain.MultiReplicaEnable = true

	rep.Kind = "OK"
}
