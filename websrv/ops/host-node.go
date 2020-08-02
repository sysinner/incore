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
	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"
	kv2 "github.com/lynkdb/kvspec/go/kvspec/v2"
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
		rs     *kv2.ObjectResult
	)
	defer c.RenderJson(&sets)

	if zoneid == status.ZoneId {
		rs = data.DataZone.NewReader(nil).KeyRangeSet(
			inapi.NsZoneSysHost(zoneid, ""), inapi.NsZoneSysHost(zoneid, "")).
			LimitNumSet(1000).Query()
	} else {
		rs = data.DataGlobal.NewReader(nil).KeyRangeSet(
			inapi.NsGlobalSysHost(zoneid, ""), inapi.NsGlobalSysHost(zoneid, "")).
			LimitNumSet(1000).Query()
	}

	for _, v := range rs.Items {

		var node inapi.ResHost

		if err := v.Decode(&node); err == nil {

			// TOPO
			if cellid != "" && (node.Operate == nil || node.Operate.CellId != cellid) {
				continue
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
		rs *kv2.ObjectResult
	)
	defer c.RenderJson(&node)

	if zoneid == status.ZoneId {
		rs = data.DataZone.NewReader(inapi.NsZoneSysHost(zoneid, nodeid)).Query()
	} else {
		rs = data.DataGlobal.NewReader(inapi.NsGlobalSysHost(zoneid, nodeid)).Query()
	}
	if rs.OK() {
		if err := rs.Decode(&node.ResHost); err != nil {
			node.Error = &types.ErrorMeta{Code: "400", Message: err.Error()}
			return
		}
	}

	if node.Meta == nil || node.Meta.Id == "" {
		node.Error = &types.ErrorMeta{"404", "HostNode Not Found"}
		return
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

	if !inapi.ResSysNodeNameReg.MatchString(set.Name) {
		set.Error = types.NewErrorMeta("400", "Invalid Node Name")
		return
	}

	if set.ZoneId != status.ZoneId {
		set.Error = types.NewErrorMeta("400", "Access Denied : Cross-Zone Console WebUI")
		return
	}

	cell := status.GlobalZoneCell(set.ZoneId, set.CellId)
	if cell == nil {
		set.Error = &types.ErrorMeta{"400", "Zone or Cell Not Setting"}
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
	hlog.Printf("info", "res/host/new addr %s", set.PeerLanAddr)

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
	node.Meta.Name = set.Name
	node.Operate.ZoneId = set.ZoneId
	node.Operate.CellId = set.CellId
	node.Operate.Action = set.Action

	//
	if node.Operate.Pr < inapi.ResSysHostPriorityMin ||
		node.Operate.Pr > inapi.ResSysHostPriorityMax {
		node.Operate.Pr = inapi.ResSysHostPriorityDefault
	}

	status.ZoneHostList.Sync(*node)

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalSysHost(node.Operate.ZoneId, node.Meta.Id), node).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	if rs := data.DataZone.NewWriter(inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id), node).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	data.DataZone.NewWriter(
		inapi.NsZoneSysHostSecretKey(set.ZoneId, node.Meta.Id), set.SecretKey).Commit()

	status.ZoneHostSecretKeys.Set(node.Meta.Id, set.SecretKey)

	// cell.NodeNum++

	/**
	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalSysCell(set.ZoneId, cell.Meta.Id), cell).Commit(); rs.OK() {
		data.DataZone.NewWriter(inapi.NsZoneSysCell(set.ZoneId, cell.Meta.Id), cell).Commit()
	} else {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}
	*/

	set.Kind = "HostNode"
}

func (c Host) NodeSetAction() {

	var set struct {
		inapi.GeneralObject
		inapi.ResHost
	}
	defer c.RenderJson(&set)

	if !status.IsZoneMasterLeader() {
		set.Error = &types.ErrorMeta{"400", "Invalid ZoneMaster Leader"}
		return
	}

	if err := c.Request.JsonDecode(&set.ResHost); err != nil {
		set.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if set.Meta == nil || set.Meta.Id == "" || set.Operate == nil {
		set.Error = &types.ErrorMeta{"400", "HostNode Not Found"}
		return
	}

	if !inapi.ResSysNodeNameReg.MatchString(set.Meta.Name) {
		set.Error = types.NewErrorMeta("400", "Invalid Node Name")
		return
	}

	if set.Operate.ZoneId != status.ZoneId {
		set.Error = types.NewErrorMeta("400", "Access Denied : Cross-Zone Console WebUI")
		return
	}

	prev := status.ZoneHostList.Item(set.Meta.Id)
	if prev == nil {
		set.Error = &types.ErrorMeta{"400", "HostNode Not Found"}
		return
	}

	prev.Meta.Updated = uint64(types.MetaTimeNow())
	if set.Operate.Action != prev.Operate.Action {
		prev.Operate.Action = set.Operate.Action
	}
	if set.Meta.Name != prev.Meta.Name {
		prev.Meta.Name = set.Meta.Name
	}

	//
	if set.Operate.Pr != prev.Operate.Pr {
		prev.Operate.Pr = set.Operate.Pr
	}
	if prev.Operate.Pr < inapi.ResSysHostPriorityMin ||
		prev.Operate.Pr > inapi.ResSysHostPriorityMax {
		prev.Operate.Pr = inapi.ResSysHostPriorityDefault
	}

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalSysHost(prev.Operate.ZoneId, prev.Meta.Id), prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	if rs := data.DataZone.NewWriter(inapi.NsZoneSysHost(prev.Operate.ZoneId, prev.Meta.Id), prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", "Server Error")
		return
	}

	set.Kind = "HostNode"
}

func (c Host) NodeSecretKeySetAction() {

	var set struct {
		inapi.GeneralObject
		ZoneId    string `json:"zone_id"`
		NodeId    string `json:"node_id"`
		SecretKey string `json:"secret_key"`
	}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if set.NodeId == "" || set.ZoneId == "" {
		set.Error = &types.ErrorMeta{"400", "Node Not Found"}
		return
	}

	if !inapi.ResSysHostSecretKeyReg.MatchString(set.SecretKey) {
		set.Error = &types.ErrorMeta{"400", "Invalid Secret Key"}
		return
	}

	prev := status.GlobalHostList.Item(set.NodeId)
	if prev == nil || prev.Operate.ZoneId != set.ZoneId {
		set.Error = &types.ErrorMeta{"400", "Node Not Found"}
		return
	}

	data.DataZone.NewWriter(
		inapi.NsZoneSysHostSecretKey(prev.Operate.ZoneId, set.NodeId), set.SecretKey).Commit()

	status.ZoneHostSecretKeys.Set(set.NodeId, set.SecretKey)

	set.Kind = "HostNode"
}
