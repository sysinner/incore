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
	"github.com/sysinner/incore/status"
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

	if c.us.UserName != "sysadmin" { // TODO
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied"))
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

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("res/compute", ""), inapi.NsGlobalPodSpec("res/compute", "")).
		LimitNumSet(100).Query()
	if rs.OK() {
		for _, v := range rs.Items {

			var item inapi.PodSpecResCompute
			if err := v.Decode(&item); err == nil {

				// datafix
				if item.Meta.ID != fmt.Sprintf("c%dm%d", item.CpuLimit, item.MemLimit) {
					data.DataGlobal.NewWriter(inapi.NsGlobalPodSpec("res/compute", item.Meta.ID), nil).
						ModeDeleteSet(true).Commit()
					continue
				}

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

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
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

	rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID)).Query()
	if rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Spec Already Exists")
		return
	}

	rs = data.DataGlobal.NewWriter(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID), set).Commit()
	if rs.OK() {
		set.Kind = "PodSpecResCompute"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Message)
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

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	var prev inapi.PodSpecResCompute
	rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("res/compute", set.Meta.ID)).Query()
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

	rs = data.DataGlobal.NewWriter(inapi.NsGlobalPodSpec("res/compute", prev.Meta.ID), set).Commit()
	if !rs.OK() {
		set.Kind = "PodSpecResCompute"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Message)
	}
}

func (c PodSpec) PlanListAction() {

	ls := inapi.PodSpecPlanList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("plan", ""), inapi.NsGlobalPodSpec("plan", "")).
		LimitNumSet(100).Query()
	for _, v := range rs.Items {

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
				data.DataGlobal.NewWriter(inapi.NsGlobalPodSpec("plan", item.Meta.ID), item).Commit()
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

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("plan", c.Params.Get("id"))).Query()
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

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	var prev inapi.PodSpecPlan
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("plan", set.Meta.ID)).Query(); rs.OK() {
		rs.Decode(&prev)
	}
	if prev.Meta.ID == "" || prev.Meta.ID != set.Meta.ID {
		prev.Meta.ID = set.Meta.ID
		prev.Meta.Created = types.MetaTimeNow()
		prev.Meta.User = "sysadmin"
	}

	//
	prev.Zones = []*inapi.PodSpecPlanZoneBound{}
	for _, zone := range status.GlobalZones {

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
		for _, cell := range zone.Cells {
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
	prev.Images = []*inapi.PodSpecPlanBoxImageBound{}
	var (
		offset = inapi.NsGlobalBoxImage("", "")
		cutset = inapi.NsGlobalBoxImage("", "")
	)
	rss := data.DataGlobal.NewReader(nil).KeyRangeSet(offset, cutset).
		LimitNumSet(100).Query()
	for _, v := range rss.Items {

		var item inapi.PodSpecBoxImage
		if err := v.Decode(&item); err != nil {
			continue
		}

		for _, v2 := range set.Images {
			if v2.RefId != item.Meta.ID {
				continue
			}
			prev.Images = append(prev.Images, &inapi.PodSpecPlanBoxImageBound{
				RefId:     item.Meta.ID,
				RefName:   item.Name,
				RefTag:    item.Tag,
				RefTitle:  item.Meta.Name,
				SortOrder: item.SortOrder,
				Driver:    item.Driver,
				OsDist:    item.OsDist,
				Arch:      item.Arch,
				// Options: item.Options,
			})
			break
		}
	}
	if len(prev.Images) < 1 {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request 04")
		return
	}
	prev.ImagesSort()
	prev.ImageDefault = prev.Images[0].RefId

	//
	prev.ResComputes = inapi.PodSpecPlanResComputeBounds{}
	rss = data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("res/compute", ""), inapi.NsGlobalPodSpec("res/compute", "")).
		LimitNumSet(100).Query()
	for _, v := range rss.Items {

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
	rss = data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("res/volume", ""), inapi.NsGlobalPodSpec("res/volume", "")).
		LimitNumSet(100).Query()
	for _, v := range rss.Items {

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
				RefName: item.Meta.Name,
				Limit:   item.Limit,
				Request: item.Request,
				Step:    item.Step,
				Default: item.Default,
				Labels:  item.Labels,
				Attrs:   item.Attrs,
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

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalPodSpec("plan", prev.Meta.ID), prev).Commit(); rs.OK() {
		set.Kind = "PodSpecPlan"
	} else {
		set.Error = types.NewErrorMeta("500", rs.Message)
	}
}

func (c PodSpec) BoxImageListAction() {

	ls := inapi.GeneralObjectList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	var (
		repo   = c.Params.Get("repo")
		action = uint32(c.Params.Int64("action"))
		offset = inapi.NsGlobalBoxImage(repo, "")
		cutset = inapi.NsGlobalBoxImage(repo, "")
	)

	// TODO
	rss := data.DataGlobal.NewReader(nil).KeyRangeSet(offset, cutset).
		LimitNumSet(100).Query()
	for _, v := range rss.Items {
		var item inapi.PodSpecBoxImage
		if err := v.Decode(&item); err != nil {
			continue
		}
		if action > 0 && action != item.Action {
			continue
		}
		ls.Items = append(ls.Items, item)
	}

	ls.Kind = "PodSpecBoxImageList"
}

func (c PodSpec) BoxImageSetAction() {

	set := inapi.GeneralObject{}
	defer c.RenderJson(&set)

	var setItem inapi.PodSpecBoxImage
	if err := c.Request.JsonDecode(&setItem); err != nil {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Bad Request")
		return
	}

	if !inapi.PodSpecImageNameReg.MatchString(setItem.Name) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Image Name")
		return
	}

	if !inapi.PodSpecImageTagReg.MatchString(setItem.Tag) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Image Tag")
		return
	}

	if setItem.Driver != inapi.PodSpecBoxImageDocker &&
		setItem.Driver != inapi.PodSpecBoxImagePouch {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Driver")
		return
	}

	if !inapi.SpecOsDistRE.MatchString(setItem.OsDist) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Dist Name")
		return
	}

	if !inapi.SpecCpuArchRE.MatchString(setItem.Arch) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Arch Name")
		return
	}

	if setItem.SortOrder < 4 {
		setItem.SortOrder = 4
	} else if setItem.SortOrder > 20 {
		setItem.SortOrder = 20
	}

	if setItem.Action != inapi.PodSpecBoxImageActionDisable {
		setItem.Action = inapi.PodSpecBoxImageActionEnable
	}

	setItem.Meta.ID = setItem.Name + ":" + setItem.Tag

	setItem.Meta.Name = strings.TrimSpace(setItem.Meta.Name)
	if setItem.Meta.Name == "" {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeInvalidArgument, "Invalid Image Name")
		return
	}

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalBoxImage(setItem.Name, setItem.Tag)).Query(); rs.OK() {
		var prev inapi.PodSpecBoxImage
		if err := rs.Decode(&prev); err == nil {
			setItem.Meta.Created = prev.Meta.Created
		}
	}

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalBoxImage(setItem.Name, setItem.Tag), setItem).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	set.Kind = "PodSpecBoxImage"
}

func (c PodSpec) ResVolumeListAction() {

	ls := inapi.GeneralObjectList{}
	defer c.RenderJson(&ls)

	if !iamclient.SessionAccessAllowed(c.Session, "sys.admin", in_conf.Config.Zone.InstanceId) {
		ls.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	// TODO
	rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("res/volume", ""), inapi.NsGlobalPodSpec("res/volume", "")).
		LimitNumSet(100).Query()
	for _, v := range rs.Items {

		var item inapi.PodSpecResVolume
		if err := v.Decode(&item); err == nil {
			ls.Items = append(ls.Items, item)
		} else {
			hlog.Printf("info", "%s, %s", err.Error(), v.String())
		}
	}

	ls.Kind = "PodSpecResVolumeList"
}
