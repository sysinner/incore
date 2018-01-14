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
	"sort"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type PodSpec struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *PodSpec) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c PodSpec) PlanEntryAction() {

	set := inapi.PodSpecPlan{}
	defer c.RenderJson(&set)

	rs := data.ZoneMaster.PvGet(inapi.NsGlobalPodSpec("plan", c.Params.Get("id")))
	if !rs.OK() {
		set.Error = types.NewErrorMeta("404", "No Spec Found")
		return
	}

	var item inapi.PodSpecPlan
	rs.Decode(&item)
	if item.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta("404", "No Spec Found")
		return
	}

	item.ChargeFix()
	sort.Sort(item.ResComputes)

	set = item
	set.Kind = "PodSpecPlan"
}

func (c PodSpec) PlanListAction() {

	ls := inapi.PodSpecPlanList{}
	defer c.RenderJson(&ls)

	// TODO
	rss := data.ZoneMaster.PvScan(inapi.NsGlobalPodSpec("plan", ""), "", "", 100).KvList()
	for _, v := range rss {
		var item inapi.PodSpecPlan
		if err := v.Decode(&item); err == nil {
			if item.Status != inapi.SpecStatusActive {
				continue
			}
			item.ChargeFix()
			sort.Sort(item.ResComputes)
			ls.Items = append(ls.Items, &item)
		}
	}

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].SortOrder < ls.Items[j].SortOrder
	})

	ls.Kind = "PodSpecPlanList"
}

func (c PodSpec) ResVolumeListAction() {

	ls := inapi.PodSpecResVolumeList{}
	defer c.RenderJson(&ls)

	rs := data.ZoneMaster.PvScan(inapi.NsGlobalPodSpec("res/volume", ""), "", "", 1000)
	rss := rs.KvList()
	for _, v := range rss {

		var item inapi.PodSpecResVolume
		if err := v.Decode(&item); err == nil {
			ls.Items = append(ls.Items, item)
		}
	}

	ls.Kind = "PodSpecResVolumeList"
}
