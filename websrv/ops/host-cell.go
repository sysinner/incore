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
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

func (c Host) CellListAction() {

	var sets inapi.GeneralObjectList
	defer c.RenderJson(&sets)

	zoneid := c.Params.Get("zoneid")

	//
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysZone(zoneid)); !rs.OK() {
		sets.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Zone Not Found",
		}
		return
	}

	//
	rss := data.GlobalMaster.PvScan(inapi.NsGlobalSysCell(zoneid, ""), "", "", 100).KvList()
	for _, v := range rss {

		var cell inapi.ResCell
		if err := v.Decode(&cell); err == nil {
			sets.Items = append(sets.Items, cell)
		}
	}

	sets.Kind = "HostCellList"
}

func (c Host) CellEntryAction() {

	var set struct {
		inapi.GeneralObject
		inapi.ResCell
	}
	defer c.RenderJson(&set)

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysCell(c.Params.Get("zoneid"), c.Params.Get("cellid"))); rs.OK() {
		rs.Decode(&set.ResCell)
	}

	if set.Meta == nil || set.Meta.Id == "" {
		set.Error = &types.ErrorMeta{"404", "Cell Not Found"}
	} else {
		set.Kind = "HostCell"
	}
}

func (c Host) CellSetAction() {

	var (
		zone inapi.ResZone
		cell struct {
			inapi.GeneralObject
			inapi.ResCell
		}
	)
	defer c.RenderJson(&cell)

	if err := c.Request.JsonDecode(&cell.ResCell); err != nil {
		cell.Error = &types.ErrorMeta{"400", err.Error()}
		return
	}

	if obj := data.GlobalMaster.PvGet(inapi.NsGlobalSysZone(cell.ZoneId)); obj.OK() {
		obj.Decode(&zone)
	}
	if zone.Meta.Id == "" {
		cell.Error = &types.ErrorMeta{"404", "Zone Not Found"}
		return
	}

	if !inapi.ResSysCellIdReg.MatchString(cell.Meta.Id) {
		cell.Error = &types.ErrorMeta{"400", "Invalid Cell ID"}
		return
	}

	cell.Meta.Updated = uint64(types.MetaTimeNow())

	// global
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id)); rs.NotFound() {

		cell.Meta.Created = uint64(types.MetaTimeNow())
	} else if rs.OK() {

		var prev inapi.ResCell
		if err := rs.Decode(&prev); err != nil {
			cell.Error = &types.ErrorMeta{"500", err.Error()}
			return
		}

		cell.Meta.Created = prev.Meta.Created

	} else {
		cell.Error = &types.ErrorMeta{"500", "ServerError"}
		return
	}

	data.GlobalMaster.PvPut(inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id),
		cell, &skv.ProgWriteOptions{
		// PrevVersion: prevVersion,
		})

	// zone
	rsp := data.ZoneMaster.PvGet(inapi.NsZoneSysCell(cell.ZoneId, cell.Meta.Id))
	if rsp.OK() {

		var prev inapi.ResCell
		if err := rsp.Decode(&prev); err == nil {
			if prev.Meta.Created != 0 {
				cell.Meta.Created = prev.Meta.Created
			}
		}
	}

	data.ZoneMaster.PvPut(inapi.NsZoneSysCell(cell.ZoneId, cell.Meta.Id), cell, nil)

	cell.Kind = "HostCell"
}
