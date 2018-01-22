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

package ops

import (
	"github.com/lessos/lessgo/types"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/rpcsrv"
	"github.com/sysinner/incore/status"
)

func (c Host) NodeListAction() {

	var (
		zoneid = c.Params.Get("zoneid")
		cellid = c.Params.Get("cellid")
		sets   inapi.GeneralObjectList
	)
	defer c.RenderJson(&sets)

	rss := data.ZoneMaster.PvScan(inapi.NsZoneSysHost(zoneid, ""), "", "", 1000).KvList()

	for _, v := range rss {

		var node inapi.ResHost

		if err := v.Decode(&node); err == nil {

			// TOPO
			if cellid != "" && (node.Operate == nil || node.Operate.CellId != cellid) {
				continue
			}

			if rs := data.ZoneMaster.PvGet(inapi.NsZoneSysHostStatus(zoneid, node.Meta.Id)); rs.OK() {

				var status inapi.ResHostStatus
				if err = rs.Decode(&status); err == nil {
					node.Status = &status
				}
			}

			sets.Items = append(sets.Items, node)
		}
	}

	sets.Kind = "HostNodeList"
}

func (c Host) NodeEntryAction() {

	var (
		zoneid = c.Params.Get("zoneid")
		nodeid = c.Params.Get("nodeid")
		node   struct {
			inapi.GeneralObject
			inapi.ResHost
		}
	)
	defer c.RenderJson(&node)

	if obj := data.ZoneMaster.PvGet(inapi.NsZoneSysHost(zoneid, nodeid)); obj.OK() {

		if err := obj.Decode(&node.ResHost); err != nil {
			node.Error = &types.ErrorMeta{Code: "400", Message: err.Error()}
			return
		}
	}

	if node.Meta == nil || node.Meta.Id == "" {
		node.Error = &types.ErrorMeta{"404", "HostNode Not Found"}
		return
	}

	if re := data.ZoneMaster.PvGet(inapi.NsZoneSysHostStatus(zoneid, node.Meta.Id)); re.OK() {

		var status inapi.ResHostStatus
		if err := re.Decode(&status); err == nil {
			node.Status = &status
		}
	}

	node.Kind = "HostNode"
}

func (c Host) NodeNewAction() {

	var set struct {
		inapi.GeneralObject
		inapi.ResHostNew
	}
	defer c.RenderJson(&set)

	if !status.IsZoneMasterLeader() {
		set.Error = &types.ErrorMeta{"400", "Invalid ZoneMaster Leader"}
		return
	}

	if err := c.Request.JsonDecode(&set.ResHostNew); err != nil {
		set.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if set.ZoneId == "" || set.CellId == "" {
		set.Error = &types.ErrorMeta{"400", "Zone or Cell Not Setting"}
		return
	}

	var cell inapi.ResCell
	if rs := data.ZoneMaster.PvGet(inapi.NsZoneSysCell(set.ZoneId, set.CellId)); !rs.OK() {
		set.Error = &types.ErrorMeta{"400", "Zone or Cell Not Setting"}
		return
	} else {
		rs.Decode(&cell)
	}

	if cell.Meta.Id != set.CellId {
		set.Error = &types.ErrorMeta{"400", "Cell Not Found"}
		return
	}

	//
	if !inapi.HostNodeAddress(set.PeerLanAddr).Valid() {
		set.Error = &types.ErrorMeta{"400", "Peer LAN Address Not Valid"}
		return
	}

	if !inapi.ResSysHostSecretKeyReg.MatchString(set.SecretKey) {
		set.Error = &types.ErrorMeta{"400", "Invalid Secret Key"}
		return
	}

	set.ZoneMasters = status.ZoneMasters()
	set.ZoneInpackServiceUrl = config.Config.InpackServiceUrl

	//
	conn, err := rpcsrv.ClientConn(set.PeerLanAddr)
	if err != nil {
		set.Error = types.NewErrorMeta("400", "Invalid Peer Address %s"+set.PeerLanAddr)
		return
	}

	node, err := inapi.NewApiHostMemberClient(conn).HostJoin(
		context.Background(), &set.ResHostNew,
	)
	if err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if node == nil || node.Meta == nil || node.Operate == nil || node.Spec == nil {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	if !inapi.ResSysHostIdReg.MatchString(node.Meta.Id) {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	node.Meta.Created = uint64(types.MetaTimeNow())
	node.Meta.Updated = uint64(types.MetaTimeNow())
	node.Operate.ZoneId = set.ZoneId
	node.Operate.CellId = set.CellId
	node.Operate.Action = set.Action

	status.ZoneHostList.Sync(*node)

	if rs := data.ZoneMaster.PvPut(inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id), node, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	data.ZoneMaster.PvPut(
		inapi.NsZoneSysHostSecretKey(set.ZoneId, node.Meta.Id), set.SecretKey, nil)

	status.ZoneHostSecretKeys.Set(node.Operate.ZoneId, set.SecretKey)

	cell.NodeNum++

	data.ZoneMaster.PvPut(inapi.NsGlobalSysCell(set.ZoneId, cell.Meta.Id), cell, nil)
	data.ZoneMaster.PvPut(inapi.NsZoneSysCell(set.ZoneId, cell.Meta.Id), cell, nil)

	set.Kind = "HostNode"
}

func (c Host) NodeSetAction() {

	var (
		node struct {
			inapi.GeneralObject
			inapi.ResHost
		}
		prev inapi.ResHost
	)
	defer c.RenderJson(&node)

	if err := c.Request.JsonDecode(&node.ResHost); err != nil {
		node.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if node.Meta == nil || node.Meta.Id == "" ||
		node.Operate == nil || node.Operate.ZoneId == "" || node.Operate.CellId == "" {
		node.Error = &types.ErrorMeta{"400", "HostNode Not Found"}
		return
	}

	//
	obj := data.ZoneMaster.PvGet(inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id))
	if obj.OK() {
		obj.Decode(&prev)
	}
	if prev.Meta == nil || prev.Meta.Id != node.Meta.Id {
		node.Error = &types.ErrorMeta{"404", "Host Not Found"}
		return
	}
	prev.Meta.Updated = uint64(types.MetaTimeNow())
	if node.Operate.Action != prev.Operate.Action {
		prev.Operate.Action = node.Operate.Action
	}
	if node.Meta.Name != prev.Meta.Name {
		prev.Meta.Name = node.Meta.Name
	}

	data.ZoneMaster.PvPut(inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id), prev, nil)

	node.Kind = "HostNode"
}
