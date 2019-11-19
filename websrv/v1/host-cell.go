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

	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

func (c Host) CellListAction() {

	var sets inapi.GeneralObjectList
	defer c.RenderJson(&sets)

	if zoneid := c.Params.Get("zoneid"); zoneid != "" {
		if zone := status.GlobalZone(zoneid); zone == nil {
			sets.Error = types.NewErrorMeta("404", "Zone Not Found")
			return
		} else {
			for _, v := range zone.Cells {
				sets.Items = append(sets.Items, v)
			}
		}
	} else {

		for _, zone := range status.GlobalZones {
			for _, v := range zone.Cells {
				sets.Items = append(sets.Items, v)
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

	cell := status.GlobalZoneCell(c.Params.Get("zoneid"), c.Params.Get("cellid"))
	if cell == nil {
		set.Error = types.NewErrorMeta("404", "Cell Not Found")
	} else {
		set.ResCell = *cell
		set.Kind = "HostCell"
	}
}
