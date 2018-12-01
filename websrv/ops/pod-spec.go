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
	"sort"
	"strings"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	in_conf "github.com/sysinner/incore/config"
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

func (c PodSpec) ResComputeListAction() {

	var ls struct {
		types.TypeMeta `json:",inline"`
		Items          inapi.PodSpecResComputes `json:"items"`
	}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("res/compute", ""), "", "", 100)
	if rs.OK() {
		rss := rs.KvList()
		for _, v := range rss {

			var item inapi.PodSpecResCompute
			if err := v.Decode(&item); err == nil {
				ls.Items = append(ls.Items, &item)
			}
		}

		if len(ls.Items) > 1 {
			sort.Sort(ls.Items)
		}
	}

	ls.Kind = "PodSpecResComputeList"
}

func (c PodSpec) ResComputeNewAction() {

	var set struct {
		inapi.GeneralObject
		inapi.PodSpecResCompute
	}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set.PodSpecResCompute); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request")
		return
	}

	if set.CpuLimit < 1 {
		set.CpuLimit = 1 // limit min to .1 cores
	} else if set.CpuLimit > 160 {
		set.CpuLimit = 160 // limit max to 16 cores
	}

	if n := set.MemLimit % 128; n > 0 {
		set.MemLimit -= n
	}
	if set.MemLimit < 128 {
		set.MemLimit = 128 // limit min to 128 MB
	} else if set.MemLimit > 32*1024 {
		set.MemLimit = 32 * 1024 // limit max to 32 GB
	}

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	name := fmt.Sprintf("c%dm%d", set.CpuLimit, set.MemLimit)
	set.Meta = types.InnerObjectMeta{
		ID:      name,
		Name:    name,
		User:    "sysadmin",
		Version: "1",
		Created: types.MetaTimeNow(),
		Updated: types.MetaTimeNow(),
	}
	set.Status = inapi.SpecStatusActive

	rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID))
	if rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Spec Already Exists")
		return
	}

	rs = data.GlobalMaster.PvPut(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID), set, nil)
	if rs.OK() {
		set.Kind = "PodSpecResCompute"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
	}
}

func (c PodSpec) ResComputeSetAction() {

	var set struct {
		inapi.GeneralObject `json:",inline"`
		inapi.PodSpecResCompute
	}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set.PodSpecResCompute); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request")
		return
	}

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	var prev inapi.PodSpecResCompute
	rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID))
	if !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Spec Not Found")
		return
	} else {
		rs.Decode(&prev)
	}
	if prev.Meta.ID == "" || prev.Meta.ID != set.Meta.ID {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Spec Not Found")
		return
	}

	prev.Status = set.Status
	prev.Meta.Updated = types.MetaTimeNow()

	rs = data.GlobalMaster.PvPut(inapi.NsGlobalPodSpec("res/compute", prev.Meta.ID), set, nil)
	if !rs.OK() {
		set.Kind = "PodSpecResCompute"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
	}
}

func (c PodSpec) PlanListAction() {

	ls := inapi.PodSpecPlanList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("plan", ""), "", "", 100)
	rss := rs.KvList()
	for _, v := range rss {

		var item inapi.PodSpecPlan
		if err := v.Decode(&item); err == nil {
			item.ChargeFix()

			upgrade := false
			for _, v2 := range item.Images {
				if strings.IndexByte(v2.RefId, ':') < 1 {
					v2.RefId = inapi.BoxImageRepoDefault + ":" + v2.RefId
					upgrade = true
				}
			}

			if item.ImageDefault != "" && strings.IndexByte(item.ImageDefault, ':') < 1 {
				item.ImageDefault = inapi.BoxImageRepoDefault + ":" + item.ImageDefault
				upgrade = true
			}

			if upgrade {
				data.GlobalMaster.PvPut(inapi.NsGlobalPodSpec("plan", item.Meta.ID), item, nil)
				hlog.Printf("warn", "v1 pod/spec/image upgrade %s", item.Meta.ID)
			}

			sort.Sort(item.ResComputes)

			ls.Items = append(ls.Items, &item)
		}
	}

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].SortOrder < ls.Items[j].SortOrder
	})

	ls.Kind = "PodSpecPlanList"
}

func (c PodSpec) PlanEntryAction() {

	set := inapi.PodSpecPlan{}
	defer c.RenderJson(&set)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan", c.Params.Get("id")))
	if rs.OK() {
		rs.Decode(&set)
	}
	if set.Meta.ID == "" || set.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "SpecPlan Not Found")
		return
	}
	set.ChargeFix()

	set.Kind = "PodSpecPlan"
}

func (c PodSpec) PlanSetAction() {

	set := inapi.PodSpecPlan{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 01")
		return
	}
	if !inapi.PodSpecPlanIdReg.MatchString(set.Meta.ID) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 02")
		return
	}

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	var prev inapi.PodSpecPlan
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan", set.Meta.ID)); rs.OK() {
		rs.Decode(&prev)
	}
	if prev.Meta.ID == "" || prev.Meta.ID != set.Meta.ID {
		prev.Meta.ID = set.Meta.ID
		prev.Meta.Created = types.MetaTimeNow()
		prev.Meta.User = "sysadmin"
	}

	//
	prev.Zones = []*inapi.PodSpecPlanZoneBound{}
	rss := data.GlobalMaster.PvScan(inapi.NsGlobalSysZone(""), "", "", 100).KvList()
	for _, v := range rss {

		var zone inapi.ResZone
		if err := v.Decode(&zone); err != nil || zone.Meta.Id == "" {
			continue
		}

		var zone_item *inapi.PodSpecPlanZoneBound
		for _, vb := range set.Zones {
			if vb.Name == zone.Meta.Id {
				zone_item = vb
				break
			}
		}

		if zone_item == nil {
			continue
		}

		var cells types.ArrayString
		rss2 := data.GlobalMaster.PvScan(inapi.NsGlobalSysCell(zone.Meta.Id, ""), "", "", 100).KvList()
		for _, v2 := range rss2 {

			var cell inapi.ResCell
			if err := v2.Decode(&cell); err != nil || cell.Meta.Id == "" {
				continue
			}

			if zone_item.Cells.Has(cell.Meta.Id) {
				cells.Set(cell.Meta.Id)
			}
		}

		if len(cells) > 0 {
			prev.Zones = append(prev.Zones, &inapi.PodSpecPlanZoneBound{
				Name:  zone.Meta.Id,
				Cells: cells,
			})
		}
	}
	if len(prev.Zones) < 1 {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 03")
		return
	}

	//
	prev.ImageDefault = ""
	prev.Images = []*inapi.PodSpecPlanBoxImageBound{}
	rss = data.GlobalMaster.PvScan(inapi.NsGlobalBoxImage(inapi.BoxImageRepoDefault, ""), "", "", 100).KvList()
	for _, v := range rss {

		var item inapi.PodSpecBoxImage
		if err := v.Decode(&item); err != nil {
			continue
		}

		for _, v2 := range set.Images {
			if v2.RefId != item.Meta.ID {
				continue
			}
			if prev.ImageDefault == "" {
				prev.ImageDefault = item.Meta.ID
			}
			prev.Images = append(prev.Images, &inapi.PodSpecPlanBoxImageBound{
				RefId:  item.Meta.ID,
				Driver: item.Driver,
				OsDist: item.OsDist,
				Arch:   item.Arch,
				// Options: item.Options,
			})
			break
		}
	}
	if len(prev.Images) < 1 {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 04")
		return
	}

	//
	prev.ResComputes = inapi.PodSpecPlanResComputeBounds{}
	rss = data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("res/compute", ""), "", "", 100).KvList()
	for _, v := range rss {

		var item inapi.PodSpecResCompute
		if err := v.Decode(&item); err != nil {
			continue
		}

		for _, v2 := range set.ResComputes {
			if v2.RefId != item.Meta.ID {
				continue
			}
			prev.ResComputes = append(prev.ResComputes, &inapi.PodSpecPlanResComputeBound{
				RefId:    item.Meta.ID,
				CpuLimit: item.CpuLimit,
				MemLimit: item.MemLimit,
			})
			break
		}
	}
	if len(prev.ResComputes) < 1 {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 05")
		return
	}
	sort.Sort(prev.ResComputes)
	prev.ResComputeDefault = prev.ResComputes[0].RefId

	//
	prev.ResVolumeDefault = ""
	prev.ResVolumes = []*inapi.PodSpecPlanResVolumeBound{}
	rss = data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("res/volume", ""), "", "", 100).KvList()
	for _, v := range rss {

		var item inapi.PodSpecResVolume
		if err := v.Decode(&item); err != nil {
			continue
		}

		for _, v2 := range set.ResVolumes {
			if v2.RefId != item.Meta.ID {
				continue
			}
			if prev.ResVolumeDefault == "" {
				prev.ResVolumeDefault = item.Meta.ID
			}
			prev.ResVolumes = append(prev.ResVolumes, &inapi.PodSpecPlanResVolumeBound{
				RefId:   item.Meta.ID,
				Limit:   item.Limit,
				Request: item.Request,
				Step:    item.Step,
				Default: item.Default,
				Labels:  item.Labels,
			})
			break
		}
	}
	if len(prev.ResVolumes) < 1 {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 06")
		return
	}

	prev.Labels = set.Labels
	prev.Annotations = set.Annotations
	prev.Meta.Name = set.Meta.Name
	prev.Status = set.Status
	prev.SortOrder = set.SortOrder

	if prev.SortOrder < 0 {
		prev.SortOrder = 0
	} else if prev.SortOrder > 15 {
		prev.SortOrder = 15
	}

	prev.Meta.Updated = types.MetaTimeNow()

	if rs := data.GlobalMaster.PvPut(inapi.NsGlobalPodSpec("plan", prev.Meta.ID), prev, nil); rs.OK() {
		set.Kind = "PodSpecPlan"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
	}
}

func (c PodSpec) BoxImageListAction() {

	ls := inapi.GeneralObjectList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	var (
		repo = c.Params.Get("repo")
	)
	if repo == "" {
		repo = inapi.BoxImageRepoDefault
	}

	// TODO
	rs := data.GlobalMaster.PvScan(inapi.NsGlobalBoxImage(repo, ""), "", "", 100)
	rss := rs.KvList()
	for _, v := range rss {

		var item inapi.PodSpecBoxImage
		if err := v.Decode(&item); err == nil {
			ls.Items = append(ls.Items, item)
		}
	}

	ls.Kind = "PodSpecBoxImageList"
}

func (c PodSpec) ResVolumeListAction() {

	ls := inapi.GeneralObjectList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("res/volume", ""), "", "", 100)
	rss := rs.KvList()
	for _, v := range rss {

		var item inapi.PodSpecResVolume
		if err := v.Decode(&item); err == nil {
			ls.Items = append(ls.Items, item)
		}
	}

	ls.Kind = "PodSpecResVolumeList"
}
