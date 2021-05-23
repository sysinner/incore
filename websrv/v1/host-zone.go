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

func (c Host) ZoneListAction() {

	ls := inapi.GeneralObjectList{}
	defer c.RenderJson(&ls)

	//
	for _, v := range status.GlobalZones {

		zone := inapi.ResZone{
			Meta: &inapi.ObjectMeta{
				Id: v.Meta.Id,
			},
			Summary:            v.Summary,
			LanAddrs:           v.LanAddrs,
			WanApi:             v.WanApi,
			Phase:              v.Phase,
			NetworkDomainName:  v.NetworkDomainName,
			NetworkVpcBridge:   v.NetworkVpcBridge,
			NetworkVpcInstance: v.NetworkVpcInstance,
		}

		if c.Params.Get("fields") == "cells" {

			for _, cell := range v.Cells {
				zone.Cells = append(zone.Cells, cell)
			}
		}

		ls.Items = append(ls.Items, zone)
	}

	ls.Kind = "HostZoneList"
}

func (c Host) ZoneEntryAction() {

	var set struct {
		inapi.GeneralObject
		inapi.ResZone
	}

	defer c.RenderJson(&set)

	item := status.GlobalZone(c.Params.Get("id"))
	if item == nil {
		set.Error = types.NewErrorMeta("400", "Zone Not Found")
	}

	set.ResZone = inapi.ResZone{
		Meta: &inapi.ObjectMeta{
			Id: item.Meta.Id,
		},
		Summary:  item.Summary,
		LanAddrs: item.LanAddrs,
		WanApi:   item.WanApi,
		Phase:    item.Phase,
	}

	if c.Params.Get("fields") == "cells" {
		for _, cell := range item.Cells {
			set.Cells = append(set.Cells, cell)
		}
	}

	set.Kind = "HostZone"
}
