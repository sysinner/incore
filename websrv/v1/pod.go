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
	"fmt"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"
	iox_utils "github.com/lynkdb/iomix/utils"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	zm_status "github.com/sysinner/incore/status"
)

var (
	pod_action_set_time_min   uint32 = 60
	pod_action_queue_time_min uint32 = 600
)

type Pod struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Pod) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c *Pod) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c Pod) ListAction() {

	var (
		ls inapi.PodList
	)

	defer c.RenderJson(&ls)

	// TODO pager
	var rs skv.Result
	if zone_id := c.Params.Get("zone_id"); zone_id != "" {
		rs = data.ZoneMaster.PvRevScan(inapi.NsZonePodInstance(zone_id, ""), "", "", 10000)
	} else {
		rs = data.GlobalMaster.PvRevScan(inapi.NsGlobalPodInstance(""), "", "", 10000)
	}
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	var exp_filter_app_notin types.ArrayString
	if v := c.Params.Get("exp_filter_app_notin"); v != "" {
		exp_filter_app_notin = types.ArrayString(strings.Split(v, ","))
	}

	var exp_filter_app_spec_res inapi.AppSpecResRequirements
	if v := c.Params.Get("exp_filter_app_spec_id"); v != "" {
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalAppSpec(v)); rs.OK() {
			var spec inapi.AppSpec
			rs.Decode(&spec)
			if spec.Meta.ID == v {
				exp_filter_app_spec_res = spec.ExpRes
			}
		}
	}

	action := uint32(c.Params.Uint64("operate_action"))

	for _, v := range rss {

		var pod inapi.Pod

		if err := v.Decode(&pod); err == nil {

			// TOPO
			if c.Params.Get("filter_meta_user") == "all" &&
				iamclient.SessionAccessAllowed(c.Session, "sysinner.admin", config.Config.InstanceId) {
				//
			} else if pod.Meta.User != c.us.UserName {
				continue
			}

			if c.Params.Int64("destroy_enable") != 1 &&
				inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
				continue
			}

			if action > 0 && !inapi.OpActionAllow(pod.Operate.Action, action) {
				continue
			}

			if len(exp_filter_app_notin) > 0 {
				found := false
				for _, vpa := range pod.Apps {
					if exp_filter_app_notin.Has(vpa.Spec.Meta.ID) {
						found = true
						break
					}
				}
				if found {
					continue
				}
			}

			if exp_filter_app_spec_res.CpuMin > 0 {
				if err := app_pod_res_check(&pod, &exp_filter_app_spec_res); err != nil {
					continue
				}
			}

			if len(fields) > 0 {

				podfs := inapi.Pod{
					Meta: types.InnerObjectMeta{
						ID: pod.Meta.ID,
					},
				}

				if fields.Has("meta/name") {
					podfs.Meta.Name = pod.Meta.Name
				}

				if fields.Has("meta/updated") {
					podfs.Meta.Updated = pod.Meta.Updated
				}

				if fields.Has("meta/user") {
					podfs.Meta.User = pod.Meta.User
				}

				if fields.Has("spec") && pod.Spec != nil {
					podfs.Spec = &inapi.PodSpecBound{}

					if fields.Has("spec/ref/id") {
						podfs.Spec.Ref.Id = pod.Spec.Ref.Id
					}

					if fields.Has("spec/ref/name") {
						podfs.Spec.Ref.Name = pod.Spec.Ref.Name
					}

					if fields.Has("spec/zone") {
						podfs.Spec.Zone = pod.Spec.Zone
					}

					if fields.Has("spec/cell") {
						podfs.Spec.Cell = pod.Spec.Cell
					}
				}

				if fields.Has("apps") {

					for _, a := range pod.Apps {

						afs := inapi.AppInstance{}

						if fields.Has("apps/meta/id") {
							afs.Meta.ID = a.Meta.ID
						}

						if fields.Has("apps/meta/name") {
							afs.Meta.Name = a.Meta.Name
						}

						podfs.Apps = append(podfs.Apps, afs)
					}
				}

				if fields.Has("operate") {

					if fields.Has("operate/action") {

						// TODO
						if pod.Spec.Zone != zm_status.ZoneId {
							if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodStatus(pod.Spec.Zone, pod.Meta.ID)); rs.OK() {
								var pst inapi.PodStatus
								if err := rs.Decode(&pst); err == nil {
									podfs.Operate.Action = pod.Operate.Action | pst.Action
								}
							}
						}

						if podfs.Operate.Action < 1 || pod.Spec.Zone == zm_status.ZoneId {
							podfs.Operate.Action = pod.Operate.Action | zm_status.ZonePodRepMergeOperateAction(pod.Meta.ID, pod.Operate.ReplicaCap)
						}
					}

					if fields.Has("operate/version") {
						podfs.Operate.Version = pod.Operate.Version
					}

					if fields.Has("operate/replica_cap") {
						podfs.Operate.ReplicaCap = pod.Operate.ReplicaCap
					}

					if fields.Has("operate/replicas") {
						podfs.Operate.Replicas = pod.Operate.Replicas
					}
				}

				ls.Items = append(ls.Items, podfs)
			} else {
				ls.Items = append(ls.Items, pod)
			}
		}
	}

	ls.Kind = "PodList"
}

func (c Pod) EntryAction() {

	var (
		id      = c.Params.Get("id")
		fields  = c.Params.Get("fields")
		zone_id = c.Params.Get("zone_id")
		set     inapi.Pod
	)

	defer c.RenderJson(&set)

	if zone_id == "" {
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(id)); rs.OK() {
			rs.Decode(&set)
			if set.Meta.ID == "" || !c.owner_or_sysadmin_allow(set.Meta.User, "sysinner.admin") {
				set = inapi.Pod{}
				set.Error = types.NewErrorMeta("404", "Pod Not Found")
				return
			}
			zone_id = set.Spec.Zone
		}
	}

	if zone_id != "" {

		if rs := data.ZoneMaster.PvGet(inapi.NsZonePodInstance(zone_id, id)); rs.OK() {

			rs.Decode(&set)
			if set.Meta.ID == "" || !c.owner_or_sysadmin_allow(set.Meta.User, "sysinner.admin") {
				set = inapi.Pod{}
				set.Error = types.NewErrorMeta("404", "Pod Not Found")
				return
			}
			if fields == "status" {
				if v := c.status(set, set.Meta.ID); v.Action != 0 {
					set.Status = &v
				} else {
					set.Status = nil
				}
			}

			// TODO
			if set.Spec.Zone == zm_status.ZoneId {
				set.Operate.Action = inapi.OpActionAppend(set.Operate.Action,
					zm_status.ZonePodRepMergeOperateAction(set.Meta.ID, set.Operate.ReplicaCap))
			}
		}
	}

	for _, v := range set.Operate.Replicas {
		if host := zm_status.GlobalHostList.Item(v.Node); host != nil {
			for _, v2 := range v.Ports {
				if i := strings.IndexByte(host.Spec.PeerLanAddr, ':'); i > 0 {
					v2.LanAddr = host.Spec.PeerLanAddr[:i]
				} else {
					v2.LanAddr = host.Spec.PeerLanAddr
				}
				v2.WanAddr = host.Spec.PeerWanAddr
			}
		}
	}

	set.Kind = "Pod"
}

func (c Pod) NewAction() {

	var (
		set       inapi.PodCreate
		spec_plan inapi.PodSpecPlan
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	set.Name = strings.TrimSpace(set.Name)
	if set.Name == "" {
		set.Error = types.NewErrorMeta("400", "Name can not be null")
		return
	}

	//
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan", set.Plan)); rs.OK() {
		rs.Decode(&spec_plan)
	}
	if spec_plan.Meta.ID == "" || spec_plan.Meta.ID != set.Plan {
		set.Error = types.NewErrorMeta("400", "Spec Not Found")
		return
	}

	//
	if err := set.Valid(spec_plan); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	spec_plan.ChargeFix()

	//
	var zone inapi.ResZone
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysZone(set.Zone)); rs.OK() {
		rs.Decode(&zone)
	}
	if zone.Meta.Id == "" {
		set.Error = types.NewErrorMeta("400", "Zone Not Found")
		return
	}

	//
	var cell inapi.ResCell
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysCell(set.Zone, set.Cell)); rs.OK() {
		rs.Decode(&cell)
	}
	if cell.Meta.Id == "" {
		set.Error = types.NewErrorMeta("400", "Cell Not Found")
		return
	}

	res_vol := spec_plan.ResVolume(set.ResVolume)
	if res_vol == nil {
		set.Error = types.NewErrorMeta("400", "No ResVolume Found")
		return
	}
	if set.ResVolumeSize < res_vol.Request {
		set.ResVolumeSize = res_vol.Request
	} else if set.ResVolumeSize > res_vol.Limit {
		set.ResVolumeSize = res_vol.Limit
	} else {
		if fix := set.ResVolumeSize % res_vol.Step; fix > 0 {
			set.ResVolumeSize += res_vol.Step
		}
	}

	tn := types.MetaTimeNow()
	id := iox_utils.Uint32ToHexString(uint32(tn.Time().Unix())) + idhash.RandHexString(8)

	pod := inapi.Pod{
		Meta: types.InnerObjectMeta{
			ID:      id,
			Name:    set.Name,
			User:    c.us.UserName,
			Created: tn,
			Updated: tn,
		},
		Spec: &inapi.PodSpecBound{
			Ref: inapi.ObjectReference{
				Id:      spec_plan.Meta.ID,
				Name:    spec_plan.Meta.Name,
				Version: spec_plan.Meta.Version,
			},
			Zone:   set.Zone,
			Cell:   set.Cell,
			Labels: spec_plan.Labels,
			Volumes: []inapi.PodSpecResVolumeBound{
				{
					Ref: inapi.ObjectReference{
						Id:   res_vol.RefId,
						Name: res_vol.RefId,
					},
					Name:      "system",
					SizeLimit: set.ResVolumeSize,
				},
			},
		},
		Operate: inapi.PodOperate{
			Action:     inapi.OpActionStart,
			Version:    1,
			ReplicaCap: 1, // TODO
			Operated:   uint32(time.Now().Unix()),
		},
	}

	//
	for _, v := range set.Boxes {

		if strings.IndexByte(v.Image, ':') < 0 { // UPGRADE
			v.Image = inapi.BoxImageRepoDefault + ":" + v.Image
			hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", id, v.Image)
		}

		img := spec_plan.Image(v.Image)
		if img == nil {
			set.Error = types.NewErrorMeta("400", "No Image Found")
			return
		}

		res := spec_plan.ResCompute(v.ResCompute)
		if res == nil {
			set.Error = types.NewErrorMeta("400", "No ResCompute Found")
			return
		}

		pod.Spec.Boxes = append(pod.Spec.Boxes, inapi.PodSpecBoxBound{
			Name:    v.Name,
			Updated: types.MetaTimeNow(),
			Image: inapi.PodSpecBoxImageBound{
				Ref: &inapi.ObjectReference{
					Id:   img.RefId,
					Name: img.RefId,
				},
				Driver: img.Driver,
				OsDist: img.OsDist,
				Arch:   img.Arch,
				// Options: img.Options,
			},
			Resources: &inapi.PodSpecBoxResComputeBound{
				Ref: &inapi.ObjectReference{
					Id:   res.RefId,
					Name: res.RefId,
				},
				CpuLimit: res.CpuLimit,
				MemLimit: res.MemLimit,
			},
		})
	}

	if v := c.Params.Get("exp_filter_app_spec_id"); v != "" {
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalAppSpec(v)); rs.OK() {
			var app_spec inapi.AppSpec
			rs.Decode(&app_spec)
			if app_spec.Meta.ID == v && app_spec.ExpRes.CpuMin > 0 {
				if err := app_pod_res_check(&pod, &app_spec.ExpRes); err != nil {
					set.Error = types.NewErrorMeta("400", err.Error())
					return
				}
			}
		}
	}

	if set.Error = podAccountChargePreValid(&pod, &spec_plan); set.Error != nil {
		return
	}

	//
	if rs := data.GlobalMaster.PvNew(inapi.NsGlobalPodInstance(pod.Meta.ID), pod, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	/*
		oplog := inapi.NewOpLog(c.us.UserName)
		if rs := data.ZoneMaster.PvNew(inapi.NsZonePodOperateLog(pod.Spec.Zone, pod.RepId(0)), oplog, nil); !rs.OK() {
			set.Error = types.NewErrorMeta("500", rs.Bytex().String())
			return
		}
	*/

	// Pod Map to Cell Queue
	sqkey := inapi.NsGlobalSetQueuePod(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	data.GlobalMaster.PvNew(sqkey, pod, nil)

	set.Pod = pod.Meta.ID
	set.Kind = "PodInstance"
}

func (c Pod) OpActionSetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	var (
		pod_id    = c.Params.Get("pod_id")
		op_action = uint32(c.Params.Uint64("op_action"))
	)

	if !inapi.PodIdReg.MatchString(pod_id) {
		set.Error = types.NewErrorMeta("400", "Invalid Pod ID")
		return
	}

	if !inapi.OpActionValid(op_action) {
		set.Error = types.NewErrorMeta("400", "Invalid OpAction")
		return
	}

	var prev inapi.Pod
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(pod_id)); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != pod_id ||
		!c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta("400", "Pod Not Found or Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta("400", "the pod instance has been destroyed")
		return
	}

	if inapi.OpActionAllow(op_action, inapi.OpActionDestroy) {
		for _, v := range prev.Apps {
			if !inapi.OpActionAllow(v.Operate.Action, inapi.OpActionDestroy) {
				set.Error = types.NewErrorMeta("400",
					fmt.Sprintf("Action Denied: the app (%s / %s) is running", v.Meta.ID, v.Meta.Name))
				return
			}
		}
	}

	tn := uint32(time.Now().Unix())

	if (inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStop) && inapi.OpActionAllow(op_action, inapi.OpActionStart)) ||
		(inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStart) && inapi.OpActionAllow(op_action, inapi.OpActionStop)) {

		if tn-prev.Operate.Operated < pod_action_set_time_min {
			set.Error = types.NewErrorMeta("400", "too many operations in 1 minute, try again later")
			return
		}
	}

	//
	prev.Operate.Action = inapi.OpActionControlFilter(op_action)
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.PvGet(sqkey); rs.OK() {
		if tn-prev.Operate.Operated < pod_action_queue_time_min {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
		}
		return
	}

	prev.Operate.Operated = tn
	if rs := data.GlobalMaster.PvPut(sqkey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, &skv.KvProgWriteOptions{
			Expired: uint64(time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second).UnixNano()),
		})
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstanceDestroyed(prev.Meta.ID), prev, nil)
	} else {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil)
	}

	set.Kind = "PodInstance"
}

func (c Pod) SetInfoAction() {

	var (
		set  inapi.Pod
		prev inapi.Pod
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if set.Operate.Action > 0 && !inapi.OpActionValid(set.Operate.Action) {
		set.Error = types.NewErrorMeta("400", "Invalid OpAction")
		return
	}

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(set.Meta.ID)); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != set.Meta.ID {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta("400", "the pod instance has been destroyed")
		return
	}

	force_sync := false
	for _, v := range prev.Spec.Boxes {
		if strings.IndexByte(v.Image.Ref.Id, ':') < 0 {
			v.Image.Ref.Id = inapi.BoxImageRepoDefault + ":" + v.Image.Ref.Id
			hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", prev.Meta.ID, v.Image.Ref.Id)
			force_sync = true
		}
	}

	//
	if !force_sync &&
		prev.Meta.Name == set.Meta.Name &&
		prev.Operate.Action == set.Operate.Action {
		set.Kind = "PodInstance"
		return
	}

	if inapi.OpActionAllow(set.Operate.Action, inapi.OpActionDestroy) {
		for _, v := range prev.Apps {
			if !inapi.OpActionAllow(v.Operate.Action, inapi.OpActionDestroy) {
				set.Error = types.NewErrorMeta("400",
					fmt.Sprintf("Action Denied: the app (%s / %s) is running", v.Meta.ID, v.Meta.Name))
				return
			}
		}
	}

	tn := uint32(time.Now().Unix())

	if (inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStop) && inapi.OpActionAllow(set.Operate.Action, inapi.OpActionStart)) ||
		(inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStart) && inapi.OpActionAllow(set.Operate.Action, inapi.OpActionStop)) {

		if tn-prev.Operate.Operated < pod_action_set_time_min {
			set.Error = types.NewErrorMeta("400", "too many operations in 1 minute, try again later")
			return
		}
	}

	prev.Meta.Name = set.Meta.Name
	if set.Operate.Action > 0 {
		prev.Operate.Action = inapi.OpActionControlFilter(set.Operate.Action)
		prev.Operate.Version++
	}

	//
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.PvGet(sqkey); rs.OK() {
		if tn-prev.Operate.Operated < pod_action_queue_time_min {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Operated = tn
	if rs := data.GlobalMaster.PvPut(sqkey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, &skv.KvProgWriteOptions{
			Expired: uint64(time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second).UnixNano()),
		})
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstanceDestroyed(prev.Meta.ID), prev, nil)
	} else {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil)
	}

	set.Kind = "PodInstance"
}

func (c Pod) DeleteAction() {

	var (
		set    types.TypeMeta
		prev   inapi.Pod
		pod_id = c.Params.Get("pod_id")
	)

	defer c.RenderJson(&set)

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(pod_id)); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != pod_id {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta("400", "the pod instance has been destroyed")
		return
	}

	for i, v := range prev.Apps {

		var app inapi.AppInstance

		rs := data.GlobalMaster.PvGet(inapi.NsGlobalAppInstance(v.Meta.ID))
		if rs.NotFound() {
			continue
		}

		if !rs.OK() {
			set.Error = types.NewErrorMeta("500", "server error "+rs.Bytex().String())
			return
		} else {
			rs.Decode(&app)
		}

		if app.Meta.ID != v.Meta.ID {
			set.Error = types.NewErrorMeta("500", fmt.Sprintf("App %s Not Found", v.Meta.ID))
			return
		}

		if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionDestroy) {
			continue
		}

		app.Operate.Action = inapi.OpActionDestroy
		app.Meta.Updated = types.MetaTimeNow()

		if rs := data.GlobalMaster.PvPut(inapi.NsGlobalAppInstance(v.Meta.ID), app, nil); !rs.OK() {
			set.Error = types.NewErrorMeta("500", rs.Bytex().String())
			return
		}

		prev.Apps[i].Operate.Action = inapi.OpActionDestroy
	}

	prev.Operate.Action = inapi.OpActionDestroy
	prev.Operate.Version++

	//
	prev.Meta.Updated = types.MetaTimeNow()

	tn := uint32(time.Now().Unix())

	// Pod Map to Cell Queue
	sqkey := inapi.NsGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.PvGet(sqkey); rs.OK() {
		if tn-prev.Operate.Operated < pod_action_set_time_min {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Operated = tn
	if rs := data.GlobalMaster.PvPut(sqkey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, &skv.KvProgWriteOptions{
			Expired: uint64(time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second).UnixNano()),
		})
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstanceDestroyed(prev.Meta.ID), prev, nil)
	} else {
		data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil)
	}

	set.Kind = "PodInstance"
}

func (c Pod) StatusAction() {
	set := c.status(inapi.Pod{}, c.Params.Get("id"))
	c.RenderJson(set)
}

func (c *Pod) status(pod inapi.Pod, pod_id string) inapi.PodStatus {

	var status inapi.PodStatus

	if pod.Meta.ID == "" {

		//
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(pod_id)); rs.OK() {
			rs.Decode(&pod)
		}

		if pod.Meta.ID == "" {
			status.Error = types.NewErrorMeta("404.01", "Pod Not Found")
			return status
		}

		//
		if rs := data.ZoneMaster.PvGet(inapi.NsZonePodInstance(pod.Spec.Zone, pod_id)); rs.OK() {
			rs.Decode(&pod)
		}

		if pod.Meta.ID == "" || !c.owner_or_sysadmin_allow(pod.Meta.User, "sysinner.admin") {
			status.Error = types.NewErrorMeta("404.02", "Pod Not Found or Access Denied")
			return status
		}
	}

	if len(pod.Operate.OpLog) > 0 {
		status.OpLog = pod.Operate.OpLog
	}

	for _, rep := range pod.Operate.Replicas {

		if rep.Node == "" {
			continue
		}

		rep_status := inapi.PbPodRepStatusSliceGet(zm_status.ZonePodRepStatusSets, pod.Meta.ID, uint32(rep.Id))
		if rep_status == nil {
			continue
		}

		if rep_status.Action == 0 {
			rep_status.Action = inapi.OpActionPending
		} else {

			if rep_status.Action == inapi.OpActionRunning &&
				(uint32(time.Now().UTC().Unix())-rep_status.Updated) > 600 {
				rep_status.Action = 0
			}

			status.Replicas = append(status.Replicas, rep_status)
		}
	}

	status.Kind = "PodStatus"

	status.Refresh(pod.Operate.ReplicaCap)

	// TODO
	if pod.Spec.Zone != zm_status.ZoneId {
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodStatus(pod.Spec.Zone, pod.Meta.ID)); rs.OK() {
			var pst inapi.PodStatus
			if err := rs.Decode(&pst); err == nil {
				status.Action = pod.Operate.Action | pst.Action
			}
		}
	}

	return status
}

func (c Pod) AccessSetAction() {

	var (
		set  inapi.Pod
		prev inapi.Pod
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if set.Operate.Access == nil {
		set.Error = types.NewErrorMeta("400", "Access Settings Not Found")
		return
	}

	if len(set.Operate.Access.SshKey) > 512 { // TODO
		set.Error = types.NewErrorMeta("400", "Invalid SSH Key")
		return
	}

	if set.Operate.Access.SshOn && len(set.Operate.Access.SshKey) < 128 {
		set.Error = types.NewErrorMeta("400", "Invalid SSH Key")
		return
	}

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(set.Meta.ID)); !rs.OK() {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != set.Meta.ID {
		set.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta("400", "the pod instance has been destroyed")
		return
	}

	if prev.Operate.Access == nil {
		prev.Operate.Access = &inapi.PodOperateAccess{}
	}

	if set.Operate.Access.SshOn != prev.Operate.Access.SshOn {
		prev.Operate.Access.SshOn = set.Operate.Access.SshOn
	}

	if prev.Operate.Access.SshOn {
		set.Operate.Access.SshKey = strings.TrimSpace(set.Operate.Access.SshKey)
		if set.Operate.Access.SshKey != prev.Operate.Access.SshKey {
			prev.Operate.Access.SshKey = set.Operate.Access.SshKey
		}
	} else {
		prev.Operate.Access.SshKey = ""
	}

	tn := uint32(time.Now().Unix())

	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.PvGet(sqkey); rs.OK() {
		if tn-prev.Operate.Operated < pod_action_queue_time_min {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
		}
		return
	}

	prev.Operate.Operated = tn
	if rs := data.GlobalMaster.PvPut(sqkey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}
	data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil)

	set.Kind = "PodInstance"
}

func (c Pod) SpecSetAction() {

	var (
		set       inapi.PodCreate
		spec_plan inapi.PodSpecPlan
		prev      inapi.Pod
	)
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if set.Pod == "" {
		set.Error = types.NewErrorMeta("400", "Pod can not be null")
		return
	}

	//
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(set.Pod)); rs.OK() {
		rs.Decode(&prev)
	}
	if prev.Meta.ID != set.Pod {
		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta("400", "the pod instance has been destroyed")
		return
	}

	if len(set.Boxes) != 1 {
		set.Error = types.NewErrorMeta("400", "invalid box/spec set")
		return
	}

	if prev.Spec.Zone != set.Zone || prev.Spec.Cell != set.Cell {
		set.Error = types.NewErrorMeta("400", "invalid zone or cell set")
		return
	}

	if set.Boxes[0].Image != "" {
		if strings.Index(set.Boxes[0].Image, ":") < 1 {
			set.Boxes[0].Image = "sysinner:" + set.Boxes[0].Image
		}
	}

	// TODO
	if len(prev.Spec.Boxes) > 0 {
		if prev.Spec.Boxes[0].Image.Ref != nil {
			if strings.Index(prev.Spec.Boxes[0].Image.Ref.Id, ":") < 1 {
				prev.Spec.Boxes[0].Image.Ref.Id = "sysinner:" + prev.Spec.Boxes[0].Image.Ref.Id
			}
			if strings.Index(prev.Spec.Boxes[0].Image.Ref.Name, ":") < 1 {
				prev.Spec.Boxes[0].Image.Ref.Name = "sysinner:" + prev.Spec.Boxes[0].Image.Ref.Name
			}

			if set.Boxes[0].Image == "" {
				set.Boxes[0].Image = prev.Spec.Boxes[0].Image.Ref.Name
			}

			if set.Boxes[0].Image != prev.Spec.Boxes[0].Image.Ref.Name {
				set.Error = types.NewErrorMeta("400", "invalid image name")
				return
			}
		}
	}

	//
	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan", set.Plan)); rs.OK() {
		rs.Decode(&spec_plan)
	}
	if spec_plan.Meta.ID == "" || spec_plan.Meta.ID != set.Plan {
		set.Error = types.NewErrorMeta("400", "Spec Not Found")
		return
	}

	//
	if err := set.Valid(spec_plan); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}
	spec_plan.ChargeFix()

	res_vol := spec_plan.ResVolume(set.ResVolume)
	if res_vol == nil {
		set.Error = types.NewErrorMeta("400", "No ResVolume Found")
		return
	}
	if set.ResVolumeSize < res_vol.Request {
		set.ResVolumeSize = res_vol.Request
	} else if set.ResVolumeSize > res_vol.Limit {
		set.ResVolumeSize = res_vol.Limit
	} else {
		if fix := set.ResVolumeSize % res_vol.Step; fix > 0 {
			set.ResVolumeSize += res_vol.Step
		}
	}

	if prev.Spec.Ref.Id != spec_plan.Meta.ID || prev.Spec.Ref.Version != spec_plan.Meta.Version {
		prev.Spec.Ref.Id = spec_plan.Meta.ID
		prev.Spec.Ref.Name = spec_plan.Meta.Name
		prev.Spec.Ref.Version = spec_plan.Meta.Version
	}

	for i, v := range prev.Spec.Volumes {

		if v.Name != "system" {
			continue
		}

		if v.Ref.Id != res_vol.RefId {
			prev.Spec.Volumes[i].Ref.Id = res_vol.RefId
			prev.Spec.Volumes[i].Ref.Name = res_vol.RefId
		}

		if v.SizeLimit != set.ResVolumeSize {
			prev.Spec.Volumes[i].SizeLimit = set.ResVolumeSize
		}
	}

	prev.Spec.Labels = spec_plan.Labels

	//
	prev.Spec.Boxes = []inapi.PodSpecBoxBound{}
	for _, v := range set.Boxes {

		if strings.IndexByte(v.Image, ':') < 0 { // UPGRADE
			v.Image = inapi.BoxImageRepoDefault + ":" + v.Image
			hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", prev.Meta.ID, v.Image)
		}

		img := spec_plan.Image(v.Image)
		if img == nil {
			set.Error = types.NewErrorMeta("400", "No Image Found")
			return
		}

		res := spec_plan.ResCompute(v.ResCompute)
		if res == nil {
			set.Error = types.NewErrorMeta("400", "No ResCompute Found")
			return
		}

		prev.Spec.Boxes = append(prev.Spec.Boxes, inapi.PodSpecBoxBound{
			Name:    v.Name,
			Updated: types.MetaTimeNow(),
			Image: inapi.PodSpecBoxImageBound{
				Ref: &inapi.ObjectReference{
					Id:   img.RefId,
					Name: img.RefId,
				},
				Driver: img.Driver,
				OsDist: img.OsDist,
				Arch:   img.Arch,
				// Options: img.Options,
			},
			Resources: &inapi.PodSpecBoxResComputeBound{
				Ref: &inapi.ObjectReference{
					Id:   res.RefId,
					Name: res.RefId,
				},
				CpuLimit: res.CpuLimit,
				MemLimit: res.MemLimit,
			},
		})
	}

	for _, app := range prev.Apps {

		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalAppSpec(app.Spec.Meta.ID)); rs.OK() {
			var app_spec inapi.AppSpec
			rs.Decode(&app_spec)
			if app_spec.Meta.ID == app.Spec.Meta.ID && app_spec.ExpRes.CpuMin > 0 {
				if err := app_pod_res_check(&prev, &app_spec.ExpRes); err != nil {
					set.Error = types.NewErrorMeta("400", err.Error())
					return
				}
			}
		}
	}

	if set.Error = podAccountChargePreValid(&prev, &spec_plan); set.Error != nil {
		return
	}

	tn := uint32(time.Now().Unix())
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	sqkey := inapi.NsGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.PvGet(sqkey); rs.OK() {
		if tn-prev.Operate.Operated < pod_action_queue_time_min {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
		}
		return
	}

	prev.Operate.Operated = tn

	//
	if rs := data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	// Pod Map to Cell Queue
	data.GlobalMaster.PvPut(sqkey, prev, nil)

	set.Pod = prev.Meta.ID
	set.Kind = "PodInstance"
}

func podAccountChargePreValid(pod *inapi.Pod, spec_plan *inapi.PodSpecPlan) *types.ErrorMeta {

	charge_amount := float64(0)

	// Volumes
	for _, v := range pod.Spec.Volumes {
		charge_amount += iamapi.AccountFloat64Round(
			spec_plan.ResVolumeCharge.CapSize*float64(v.SizeLimit/inapi.ByteMB), 4)
	}

	for _, v := range pod.Spec.Boxes {

		if v.Resources != nil {
			// CPU
			charge_amount += iamapi.AccountFloat64Round(
				spec_plan.ResComputeCharge.Cpu*(float64(v.Resources.CpuLimit)/1000), 4)

			// RAM
			charge_amount += iamapi.AccountFloat64Round(
				spec_plan.ResComputeCharge.Mem*float64(v.Resources.MemLimit/inapi.ByteMB), 4)
		}
	}

	charge_amount = charge_amount * float64(pod.Operate.ReplicaCap)

	charge_cycle_min := float64(3600)
	charge_amount = iamapi.AccountFloat64Round(charge_amount*(charge_cycle_min/3600), 2)
	if charge_amount < 0.01 {
		charge_amount = 0.01
	}

	tn := uint32(time.Now().Unix())
	if rsp := iamclient.AccountChargePreValid(iamapi.AccountChargePrepay{
		User:      pod.Meta.User,
		Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
		Prepay:    charge_amount,
		TimeStart: tn,
		TimeClose: tn + uint32(charge_cycle_min),
	}, zm_status.ZonePodChargeAccessKey()); rsp.Error != nil {
		return rsp.Error
	} else if rsp.Kind != "AccountCharge" {
		return types.NewErrorMeta("400", "Network Error")
	}

	return nil
}
