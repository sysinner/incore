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

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
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

	var (
		node struct {
			inapi.GeneralObject
			inapi.ResHost
		}
		cell inapi.ResCell
	)
	defer c.RenderJson(&node)

	if err := c.Request.JsonDecode(&node.ResHost); err != nil {
		node.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if !inapi.ResSysHostIdReg.MatchString(node.Meta.Id) {
		node.Error = &types.ErrorMeta{"400", "Invalid Node Id"}
		return
	}

	if node.Operate == nil || node.Operate.ZoneId == "" || node.Operate.CellId == "" {
		node.Error = &types.ErrorMeta{"400", "Zone or Cell Not Setting"}
		return
	}
	if rs := data.ZoneMaster.PvGet(inapi.NsZoneSysCell(node.Operate.ZoneId, node.Operate.CellId)); !rs.OK() {
		node.Error = &types.ErrorMeta{"400", "Zone or Cell Not Setting"}
		return
	}

	//
	if !inapi.HostNodeAddress(node.Spec.PeerLanAddr).Valid() {
		node.Error = &types.ErrorMeta{"400", "Peer LAN Address Not Valid"}
		return
	}

	// if !host_sk_re.MatchString(node.Spec.SecretKey) {
	// 	node.Error = &types.ErrorMeta{"400", "Invalid Secret Key"}
	// 	return
	// }

	if node.Spec.Capacity.Cpu < 1 || node.Spec.Capacity.Memory < 128*1024*1024 {
		node.Error = &types.ErrorMeta{"400", "Invalid Capacity.Cpu or Memory"}
		return
	}

	if obj := data.ZoneMaster.PvGet(inapi.NsZoneSysCell(node.Operate.ZoneId, node.Operate.CellId)); obj.OK() {
		obj.Decode(&cell)
	}
	if cell.Meta.Id == "" {
		node.Error = &types.ErrorMeta{"400", "Zone or Cell Not Found"}
		return
	}

	node.Meta.Created = uint64(types.MetaTimeNow())
	node.Meta.Updated = uint64(types.MetaTimeNow())

	data.ZoneMaster.PvPut(inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id), node, nil)

	node.Kind = "HostNode"
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
