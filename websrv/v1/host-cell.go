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

package v1

import (
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

func (c Host) CellListAction() {

	var sets inapi.GeneralObjectList
	defer c.RenderJson(&sets)

	zones := []string{}

	if zoneid := c.Params.Get("zoneid"); zoneid != "" {
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysZone(zoneid)); !rs.OK() {
			sets.Error = types.NewErrorMeta("404", "Zone Not Found")
			return
		}
		zones = append(zones, zoneid)
	} else {

		rss := data.GlobalMaster.PvScan(inapi.NsGlobalSysZone(""), "", "", 100).KvList()
		for _, v := range rss {
			var zone inapi.ResZone
			if err := v.Decode(&zone); err == nil {
				zones = append(zones, zone.Meta.Id)
			}
		}
	}

	//
	for _, z := range zones {
		rss := data.GlobalMaster.PvScan(inapi.NsGlobalSysCell(z, ""), "", "", 100).KvList()
		for _, v := range rss {
			var cell inapi.ResCell
			if err := v.Decode(&cell); err == nil {
				sets.Items = append(sets.Items, cell)
			}
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
		set.Error = types.NewErrorMeta("404", "Cell Not Found")
	} else {
		set.Kind = "HostCell"
	}
}
