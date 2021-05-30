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
	"fmt"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"
	kv2 "github.com/lynkdb/kvspec/go/kvspec/v2"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inrpc"
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
	set.ZoneInpackServiceUrl = config.Config.Zone.InpackServiceUrl

	//
	conn, err := inrpc.ClientConn(set.PeerLanAddr)
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

	if err := data.SysHostUpdate(node.Operate.ZoneId, node); err != nil {
		set.Error = types.NewErrorMeta("500", "Server Error : "+err.Error())
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

	/**
	if set.Operate.ZoneId != status.ZoneId {
		set.Error = types.NewErrorMeta("400", "Access Denied : Cross-Zone Console WebUI")
		return
	}
	*/

	var (
		prev *inapi.ResHost
	)

	if !status.IsZoneMasterLeader() {

		var host inapi.ResHost
		if rs := data.DataGlobal.NewReader(
			inapi.NsGlobalSysHost(set.Operate.ZoneId, set.Meta.Id)).Query(); rs.OK() {
			rs.Decode(&host)
		}

		if host.Meta.Id != set.Meta.Id {
			set.Error = &types.ErrorMeta{"400", "node not found"}
			return
		}

		const ttl uint32 = 86400 * 30
		tn := uint32(time.Now().Unix())
		if (host.Status.Updated + ttl) < tn {
			prev = &host
		} else {
			set.Error = &types.ErrorMeta{"400", "Invalid ZoneMaster Leader"}
			return
		}
	}

	if prev == nil {
		if prev = status.ZoneHostList.Item(set.Meta.Id); prev == nil {
			set.Error = &types.ErrorMeta{"400", "HostNode Not Found"}
			return
		}
	}

	if inapi.OpActionAllow(set.Operate.Action, inapi.OpActionDestroy) && prev.Operate.BoxNum > 0 {
		set.Error = &types.ErrorMeta{"400",
			fmt.Sprintf("Operation Denied: currently %d instances running on this node", prev.Operate.BoxNum),
		}
		return
	}

	prev.Meta.Updated = uint64(types.MetaTimeNow())
	if set.Operate.Action != prev.Operate.Action {
		prev.Operate.Action = inapi.SysHostActionFilter(set.Operate.Action)
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

	if inapi.OpActionAllow(set.Operate.Action, inapi.OpActionDestroy) &&
		inapi.OpActionAllow(set.Operate.Action, inapi.OpActionForce) {
		if err := data.SysHostDelete(status.ZoneId, prev); err != nil {
			set.Error = types.NewErrorMeta("500", "Server Error : "+err.Error())
			return
		}

	} else if err := data.SysHostUpdate(status.ZoneId, prev); err != nil {
		set.Error = types.NewErrorMeta("500", "Server Error : "+err.Error())
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
