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
	iox_utils "github.com/lynkdb/iomix/utils"
	kv2 "github.com/lynkdb/kvspec/go/kvspec/v2"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	podActionSetTimeMin   uint32 = 60
	podActionQueueTimeMin uint32 = 600
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
	if c.us.AccessAllow(user) ||
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
	var rs *kv2.ObjectResult
	if zone_id := c.Params.Get("zone_id"); zone_id != "" {
		rs = data.DataZone.NewReader(nil).ModeRevRangeSet(true).KeyRangeSet(
			inapi.NsZonePodInstance(zone_id, "zzzz"), inapi.NsZonePodInstance(zone_id, "")).
			LimitNumSet(10000).Query()
	} else {
		rs = data.DataGlobal.NewReader(nil).ModeRevRangeSet(true).KeyRangeSet(
			inapi.NsGlobalPodInstance("zzzz"), inapi.NsGlobalPodInstance("")).
			LimitNumSet(10000).Query()
	}

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
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(v)).Query(); rs.OK() {
			var spec inapi.AppSpec
			rs.Decode(&spec)
			if spec.Meta.ID == v {
				exp_filter_app_spec_res = spec.ExpRes
			}
		}
	}

	var exp_filter_host_id string
	if v := c.Params.Get("exp_filter_host_id"); v != "" {
		exp_filter_host_id = v
	}

	action := uint32(c.Params.Uint64("operate_action"))

	for _, v := range rs.Items {

		var pod inapi.Pod

		if err := v.Decode(&pod); err != nil {
			continue
		}

		// TOPO
		if c.Params.Get("filter_meta_user") == "all" &&
			iamclient.SessionAccessAllowed(c.Session, "sysinner.admin", config.Config.InstanceId) {
			//
		} else if pod.Meta.User != c.us.UserName &&
			!iamapi.ArrayStringHas(c.us.Groups, pod.Meta.User) {
			continue
		}

		if c.Params.Int64("destroy_enable") != 1 &&
			inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
			continue
		}

		if exp_filter_host_id != "" {
			hostHit := false
			for _, rep := range pod.Operate.Replicas {
				if rep.Node == exp_filter_host_id {
					hostHit = true
					break
				}
			}
			if !hostHit {
				continue
			}
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
			if err := appPodResCheck(&pod, &exp_filter_app_spec_res); err != nil {
				continue
			}
		}

		if len(fields) > 0 {

			podfs := &inapi.Pod{
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

				if fields.Has("spec/vol_sys") {
					podfs.Spec.VolSys = pod.Spec.VolSys
				}

				if fields.Has("spec/box") {
					podfs.Spec.Box = pod.Spec.Box
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

					podfs.Apps = append(podfs.Apps, &afs)
				}
			}

			if fields.Has("operate") {

				if fields.Has("operate/action") {
					podfs.Operate.Action = pod.Operate.Action
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
			ls.Items = append(ls.Items, &pod)
		}
	}

	if rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsKvGlobalPodUserTransfer(""), inapi.NsKvGlobalPodUserTransfer("")).
		LimitNumSet(1000).Query(); rs.OK() {

		for _, v := range rs.Items {
			var it inapi.PodUserTransfer
			if err := v.Decode(&it); err == nil {
				if c.us.AccessAllow(it.UserTo) {
					ls.UserTransfers = append(ls.UserTransfers, &it)
				}
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
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(id)).Query(); rs.OK() {
			if err := rs.Decode(&set); err != nil {
				set.Error = types.NewErrorMeta("404", "Pod Not Found "+err.Error())
				return
			}
			if set.Meta.ID == "" || !c.owner_or_sysadmin_allow(set.Meta.User, "sysinner.admin") {
				set = inapi.Pod{}
				set.Error = types.NewErrorMeta("404", "Pod Not Found")
				return
			}
			zone_id = set.Spec.Zone
		} else {
			hlog.Printf("info", "pod %s not found", id)
		}
	}

	if zone_id != "" {

		if rs := data.DataZone.NewReader(inapi.NsZonePodInstance(zone_id, id)).Query(); rs.OK() {
			if err := rs.Decode(&set); err != nil {
				set.Error = types.NewErrorMeta("404", "Pod Not Found "+err.Error())
				return
			}
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
		}
	}

	if set.Meta.ID == "" {
		set.Error = types.NewErrorMeta("404", "Pod Not Found")
		return
	}

	for _, v := range set.Operate.Replicas {
		if host := status.GlobalHostList.Item(v.Node); host != nil {
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
		owner     = c.us.UserName
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if set.Owner != "" && set.Owner != c.us.UserName {
		if !iamapi.ArrayStringHas(c.us.Groups, set.Owner) {
			set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied,
				"Access Denied to bind owner to "+set.Owner)
			return
		}
		owner = set.Owner
	}

	set.Name = strings.TrimSpace(set.Name)
	if set.Name == "" {
		set.Error = types.NewErrorMeta("400", "Name can not be null")
		return
	}

	//
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("plan", set.Plan)).Query(); rs.OK() {
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
	zone := status.GlobalZone(set.Zone)
	if zone == nil {
		set.Error = types.NewErrorMeta("400", "Zone Not Found")
		return
	}

	//
	cell := status.GlobalZoneCell(set.Zone, set.Cell)
	if cell == nil {
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
			User:    owner,
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
			VolSys: &inapi.ResVolBound{
				RefId:   res_vol.RefId,
				RefName: res_vol.RefName,
				Attrs:   res_vol.Attrs,
				Size:    set.ResVolumeSize,
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
	if strings.IndexByte(set.Box.Image, ':') < 0 { // UPGRADE
		set.Box.Image = inapi.BoxImageRepoDefault + ":" + set.Box.Image
		hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", id, set.Box.Image)
	}

	img := spec_plan.Image(set.Box.Image)
	if img == nil {
		set.Error = types.NewErrorMeta("400", "No Image Found")
		return
	}

	res := spec_plan.ResCompute(set.Box.ResCompute)
	if res == nil {
		set.Error = types.NewErrorMeta("400", "No ResCompute Found")
		return
	}

	pod.Spec.Box = inapi.PodSpecBoxBound{
		Name:    set.Box.Name,
		Updated: types.MetaTimeNow(),
		Image: inapi.PodSpecBoxImageBound{
			Ref: &inapi.ObjectReference{
				Id:   img.RefId,
				Name: img.RefId,
			},
			RefName:  img.RefName,
			RefTag:   img.RefTag,
			RefTitle: img.RefTitle,
			Driver:   img.Driver,
			OsDist:   img.OsDist,
			Arch:     img.Arch,
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
	}

	if v := c.Params.Get("exp_filter_app_spec_id"); v != "" {
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(v)).Query(); rs.OK() {
			var app_spec inapi.AppSpec
			rs.Decode(&app_spec)
			if app_spec.Meta.ID == v && app_spec.ExpRes.CpuMin > 0 {
				if err := appPodResCheck(&pod, &app_spec.ExpRes); err != nil {
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
	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(pod.Meta.ID), pod).
		ModeCreateSet(true).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	data.DataGlobal.NewWriter(sqkey, pod).Commit()

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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(pod_id)).Query(); !rs.OK() {
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
		(inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStart) && inapi.OpActionAllow(op_action, inapi.OpActionStop)) ||
		inapi.OpActionAllow(op_action, inapi.OpActionRestart) {

		if tn-prev.Operate.Operated < podActionSetTimeMin {
			set.Error = types.NewErrorMeta("400", "too many operations in 1 minute, try again later")
			return
		}
	}

	//
	prev.Operate.Action = inapi.OpActionControlFilter(op_action)
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
		if (prev.Operate.Operated + podActionQueueTimeMin) > tn {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
		}
		return
	}

	if inapi.OpActionAllow(op_action, inapi.OpActionRestart) {
		prev.Operate.Action = inapi.OpActionRemove(prev.Operate.Action, inapi.OpActionRestart)
	}

	prev.Operate.Operated = tn
	if rs := data.DataGlobal.NewWriter(sqkey, prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).
			ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
		data.DataGlobal.NewWriter(inapi.NsKvGlobalPodInstanceDestroyed(prev.Meta.ID), prev).
			Commit()
	} else {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).Commit()
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

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(set.Meta.ID)).Query(); !rs.OK() {
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
	if strings.IndexByte(prev.Spec.Box.Image.Ref.Id, ':') < 0 {
		prev.Spec.Box.Image.Ref.Id = inapi.BoxImageRepoDefault + ":" + prev.Spec.Box.Image.Ref.Id
		hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", prev.Meta.ID, prev.Spec.Box.Image.Ref.Id)
		force_sync = true
	}

	//
	if err := prev.OpSysStateValid(set.Operate.ExpSysState); err != nil {
		set.Error = types.NewErrorMeta("400", "SysState Valid Error : "+err.Error())
		return
	}

	if prev.Operate.Deploy == nil {
		prev.Operate.Deploy = &inapi.PodOperateDeploy{}
	}
	if set.Operate.Deploy == nil {
		set.Operate.Deploy = &inapi.PodOperateDeploy{}
	}

	//
	if config.Config.ZoneMaster != nil &&
		config.Config.ZoneMaster.MultiReplicaEnable {

		if err := prev.OpRepCapValid(set.Operate.ReplicaCap); err != nil {
			set.Error = types.NewErrorMeta("400", "ReplicaCap Valid Error : "+err.Error())
			return
		}

		if set.Operate.ReplicaCap > prev.Operate.ReplicaCap {

			if set.Operate.Deploy.AllocHostRepeatEnable {
				//
			} else if cell := status.GlobalZoneCell(prev.Spec.Zone, prev.Spec.Cell); cell != nil {
				if int32(prev.Operate.ReplicaCap+1) > cell.NodeNum {
					set.Error = types.NewErrorMeta("400",
						"Not enough resources to Allocate to replicas, please set a smaller value")
					return
				}
			}
		}

	} else {
		set.Operate.ReplicaCap = prev.Operate.ReplicaCap
	}

	//
	if !force_sync &&
		prev.Meta.Name == set.Meta.Name &&
		prev.Operate.Action == set.Operate.Action &&
		prev.Operate.ReplicaCap == set.Operate.ReplicaCap &&
		prev.Operate.ExpSysState == set.Operate.ExpSysState &&
		prev.Operate.Deploy.AllocHostRepeatEnable == set.Operate.Deploy.AllocHostRepeatEnable {
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

		if tn-prev.Operate.Operated < podActionSetTimeMin {
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
	prev.Operate.ExpSysState = set.Operate.ExpSysState
	if config.Config.ZoneMaster.MultiReplicaEnable {
		prev.Operate.ReplicaCap = set.Operate.ReplicaCap

		if set.Operate.Deploy != nil {
			if prev.Operate.Deploy == nil {
				prev.Operate.Deploy = &inapi.PodOperateDeploy{}
			}
			prev.Operate.Deploy.AllocHostRepeatEnable = set.Operate.Deploy.AllocHostRepeatEnable
		}
	}

	//
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
		if (prev.Operate.Operated + podActionQueueTimeMin) > tn {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Operated = tn
	if rs := data.DataGlobal.NewWriter(sqkey, prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).
			ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
		data.DataGlobal.NewWriter(inapi.NsKvGlobalPodInstanceDestroyed(prev.Meta.ID), prev).Commit()
	} else {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).Commit()
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

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(pod_id)).Query(); !rs.OK() {
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

		rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(v.Meta.ID)).Query()
		if rs.NotFound() {
			continue
		}

		if !rs.OK() {
			set.Error = types.NewErrorMeta("500", "server error "+rs.Message)
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

		if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(v.Meta.ID), app).Commit(); !rs.OK() {
			set.Error = types.NewErrorMeta("500", rs.Message)
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
	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
		if tn-prev.Operate.Operated < podActionSetTimeMin {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Operated = tn
	if rs := data.DataGlobal.NewWriter(sqkey, prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).
			ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
		data.DataGlobal.NewWriter(inapi.NsKvGlobalPodInstanceDestroyed(prev.Meta.ID), prev).Commit()
	} else {
		data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).Commit()
	}

	set.Kind = "PodInstance"
}

func (c Pod) StatusAction() {
	set := c.status(inapi.Pod{}, c.Params.Get("id"))
	c.RenderJson(set)
}

func (c *Pod) status(pod inapi.Pod, pod_id string) inapi.PodStatus {

	var podStatus inapi.PodStatus

	// podStatus := status.ZonePodStatusList.Get(

	if pod.Meta.ID == "" {

		//
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(pod_id)).Query(); rs.OK() {
			rs.Decode(&pod)
		}

		if pod.Meta.ID == "" || !c.owner_or_sysadmin_allow(pod.Meta.User, "sysinner.admin") {
			podStatus.Error = types.NewErrorMeta("404.02", "Pod Not Found or Access Denied")
			return podStatus
		}
	}

	if pod.Spec.Zone == status.ZoneId {

		if v := status.ZonePodStatusList.Get(pod.Meta.ID); v != nil {
			podStatus = *v
		}

	} else {
		if rs := data.DataGlobal.NewReader(inapi.NsKvGlobalPodStatus(pod.Spec.Zone, pod.Meta.ID)).Query(); rs.OK() {
			rs.Decode(&podStatus)
		}
	}

	if podStatus.PodId == pod.Meta.ID {
		podStatus.Kind = "PodStatus"
	}

	return podStatus
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

	set.Operate.Access.SshKey = strings.TrimSpace(set.Operate.Access.SshKey)
	set.Operate.Access.SshPwd = strings.TrimSpace(set.Operate.Access.SshPwd)

	if set.Operate.Access.SshOn {

		if set.Operate.Access.SshKey != "" {

			var (
				keys    = strings.Split(set.Operate.Access.SshKey, "\n")
				keySets = []string{}
			)

			for _, v := range keys {

				v = strings.TrimSpace(v)

				if len(v) < 2048 && len(v) > 128 {
					keySets = append(keySets, v)
				}
			}

			if len(keySets) == 0 {
				set.Error = types.NewErrorMeta("400", "incorrect SSH public Key or Key not found")
				return
			}

			set.Operate.Access.SshKey = strings.Join(keySets, "\n")
		}

		if set.Operate.Access.SshPwd != "" &&
			set.Operate.Access.SshPwd != "********" {
			if len(set.Operate.Access.SshPwd) < 8 {
				set.Error = types.NewErrorMeta("400", "Password must be more than 8 characters long")
				return
			}
			if len(set.Operate.Access.SshPwd) > 50 {
				set.Error = types.NewErrorMeta("400", "Password must be less than 50 characters long")
				return
			}
		}
	}

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(set.Meta.ID)).Query(); !rs.OK() {
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

	if prev.Operate.Access.SshOn != set.Operate.Access.SshOn {
		prev.Operate.Access.SshOn = set.Operate.Access.SshOn
	}

	if prev.Operate.Access.SshOn {
		if len(set.Operate.Access.SshKey) > 0 &&
			prev.Operate.Access.SshKey != set.Operate.Access.SshKey {
			prev.Operate.Access.SshKey = set.Operate.Access.SshKey
		}

		if set.Operate.Access.SshPwd == "********" {
			set.Operate.Access.SshPwd = ""
		}
		if len(set.Operate.Access.SshPwd) > 0 &&
			prev.Operate.Access.SshPwd != set.Operate.Access.SshPwd {
			prev.Operate.Access.SshPwd = set.Operate.Access.SshPwd
		}
		if prev.Operate.Access.SshKey == "" && prev.Operate.Access.SshPwd == "" {
			set.Error = types.NewErrorMeta("400", "SSH Public Key or Password Not Found")
			return
		}
	} else {
		prev.Operate.Access.SshKey = ""
		prev.Operate.Access.SshPwd = ""
	}

	tn := uint32(time.Now().Unix())

	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
		if (prev.Operate.Operated + podActionQueueTimeMin) > tn {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
		}
		return
	}

	prev.Operate.Operated = tn
	if rs := data.DataGlobal.NewWriter(sqkey, prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "server error, please try again later")
		return
	}
	data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).Commit()

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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(set.Pod)).Query(); rs.OK() {
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

	if prev.Spec.Zone != set.Zone || prev.Spec.Cell != set.Cell {
		set.Error = types.NewErrorMeta("400", "invalid zone or cell set")
		return
	}

	if set.Box.Image != "" {
		if strings.Index(set.Box.Image, ":") < 1 {
			set.Box.Image = "sysinner:" + set.Box.Image
		}
	}

	if prev.Spec.Box.Image.Ref != nil {
		if strings.Index(prev.Spec.Box.Image.Ref.Id, ":") < 1 {
			prev.Spec.Box.Image.Ref.Id = "sysinner:" + prev.Spec.Box.Image.Ref.Id
		}
		if strings.Index(prev.Spec.Box.Image.Ref.Name, ":") < 1 {
			prev.Spec.Box.Image.Ref.Name = "sysinner:" + prev.Spec.Box.Image.Ref.Name
		}

		if set.Box.Image == "" {
			set.Box.Image = prev.Spec.Box.Image.Ref.Id
		}

		/**
		if set.Box.Image != prev.Spec.Box.Image.Ref.Name {
			set.Error = types.NewErrorMeta("400", "invalid image name")
			return
		}
		*/
	}

	//
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("plan", set.Plan)).Query(); rs.OK() {
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

	if prev.Spec.VolSys == nil {
		prev.Spec.VolSys = &inapi.ResVolBound{}
	}

	prev.Spec.VolSys.RefId = res_vol.RefId
	prev.Spec.VolSys.RefName = res_vol.RefName
	prev.Spec.VolSys.Attrs = res_vol.Attrs
	prev.Spec.VolSys.Size = set.ResVolumeSize

	prev.Spec.Labels = spec_plan.Labels

	//
	if strings.IndexByte(set.Box.Image, ':') < 0 { // UPGRADE
		set.Box.Image = inapi.BoxImageRepoDefault + ":" + set.Box.Image
		hlog.Printf("warn", "v1 pod/spec/image upgrade %s %s", prev.Meta.ID, set.Box.Image)
	}

	img := spec_plan.Image(set.Box.Image)
	if img == nil {
		set.Error = types.NewErrorMeta("400", "No Image Found")
		return
	}

	/**
	if prev.Spec.Box.Image.Ref != nil &&
		prev.Spec.Box.Image.Driver != img.Driver {
		set.Error = types.NewErrorMeta("400", "Invalid Image")
		return
	}
	*/

	res := spec_plan.ResCompute(set.Box.ResCompute)
	if res == nil {
		set.Error = types.NewErrorMeta("400", "No ResCompute Found")
		return
	}

	prev.Spec.Box = inapi.PodSpecBoxBound{
		Name:    set.Box.Name,
		Updated: types.MetaTimeNow(),
		Image: inapi.PodSpecBoxImageBound{
			Ref: &inapi.ObjectReference{
				Id:   img.RefId,
				Name: img.RefId,
			},
			RefName:  img.RefName,
			RefTag:   img.RefTag,
			RefTitle: img.RefTitle,
			Driver:   img.Driver,
			OsDist:   img.OsDist,
			Arch:     img.Arch,
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
	}

	for _, app := range prev.Apps {

		if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(app.Spec.Meta.ID)).Query(); rs.OK() {
			var app_spec inapi.AppSpec
			rs.Decode(&app_spec)
			if app_spec.Meta.ID == app.Spec.Meta.ID && app_spec.ExpRes.CpuMin > 0 {
				if err := appPodResCheck(&prev, &app_spec.ExpRes); err != nil {
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

	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
		if (prev.Operate.Operated + podActionQueueTimeMin) > tn {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Operated = tn

	//
	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(prev.Meta.ID), prev).Commit(); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	// Pod Map to Cell Queue
	data.DataGlobal.NewWriter(sqkey, prev).ModeCreateSet(true).Commit()

	set.Pod = prev.Meta.ID
	set.Kind = "PodInstance"
}

func podAccountChargePreValid(pod *inapi.Pod, spec_plan *inapi.PodSpecPlan) *types.ErrorMeta {

	if pod.Spec.VolSys == nil {
		return types.NewErrorMeta("400", "No PodSpec/VolSys Setup")
	}

	// Volume
	charge_amount := iamapi.AccountFloat64Round(
		spec_plan.VolCharge(pod.Spec.VolSys.RefId)*float64(pod.Spec.VolSys.Size), 4)

	if pod.Spec.Box.Resources != nil {
		// CPU
		charge_amount += iamapi.AccountFloat64Round(
			spec_plan.ResComputeCharge.Cpu*(float64(pod.Spec.Box.Resources.CpuLimit)/10), 4)

		// RAM
		charge_amount += iamapi.AccountFloat64Round(
			spec_plan.ResComputeCharge.Mem*float64(pod.Spec.Box.Resources.MemLimit), 4)
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
	}, status.ZonePodChargeAccessKey()); rsp.Error != nil {
		return rsp.Error
	} else if rsp.Kind != "AccountCharge" {
		return types.NewErrorMeta("400", "Network Error")
	}

	return nil
}
