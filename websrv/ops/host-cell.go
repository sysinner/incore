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

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

func (c Host) CellListAction() {

	var sets inapi.GeneralObjectList
	defer c.RenderJson(&sets)

	zoneid := c.Params.Get("zoneid")

	zone := status.GlobalZone(zoneid)
	if zone == nil {
		sets.Error = &types.ErrorMeta{
			Code:    "404",
			Message: "Zone Not Found",
		}
		return
	}
	for _, v := range zone.Cells {
		sets.Items = append(sets.Items, v)
	}

	sets.Kind = "HostCellList"
}

func (c Host) CellEntryAction() {

	var set struct {
		inapi.GeneralObject
		inapi.ResCell
	}
	defer c.RenderJson(&set)

	if rs := data.DataGlobal.NewReader(
		inapi.NsGlobalSysCell(c.Params.Get("zoneid"), c.Params.Get("cellid"))).Query(); rs.OK() {
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

	if cell.Meta == nil {
		cell.Error = &types.ErrorMeta{"400", "invalid request"}
		return
	}

	if !inapi.ResSysCellIdReg.MatchString(cell.Meta.Id) {
		cell.Error = &types.ErrorMeta{"400", "Invalid Cell ID"}
		return
	}

	pCell := status.GlobalZoneCell(cell.ZoneId, cell.Meta.Id)

	if pCell != nil {

		if pCell.Meta.Name != cell.Meta.Name {
			pCell.Meta.Name = cell.Meta.Name
		}

		if pCell.Description != cell.Description {
			pCell.Description = cell.Description
		}

		if pCell.Phase != cell.Phase {
			pCell.Phase = cell.Phase
		}

		cell.ResCell = *pCell

		hlog.Printf("info", "cell %s : %s updated", cell.Meta.Id, cell.Meta.Name)

	} else {

		if rs := data.DataGlobal.NewReader(inapi.NsGlobalSysZone(cell.ZoneId)).Query(); rs.OK() {
			rs.Decode(&zone)
		}

		if zone.Meta.Id == "" {
			cell.Error = &types.ErrorMeta{"404", "Zone Not Found"}
			return
		}

		// global
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id)).Query(); rs.NotFound() {

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
	}

	cell.Meta.Updated = uint64(types.MetaTimeNow())

	if rs := data.DataGlobal.NewWriter(
		inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id), cell.ResCell).Commit(); !rs.OK() {
		cell.Error = &types.ErrorMeta{"500", rs.Message}
		return
	}

	if cell.ZoneId == status.ZoneId {
		if rs := data.DataZone.NewWriter(
			inapi.NsZoneSysCell(cell.ZoneId, cell.Meta.Id), cell.ResCell).Commit(); !rs.OK() {
			cell.Error = &types.ErrorMeta{"500", rs.Message}
			return
		}
	}

	cell.Kind = "HostCell"
}
