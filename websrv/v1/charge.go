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
	"strconv"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type Charge struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Charge) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c Charge) PodEstimateAction() {

	var (
		rsp         inapi.PodEstimateList
		set         inapi.PodCreate
		spec_plan   inapi.PodSpecPlan
		fields      = types.ArrayString(strings.Split(c.Params.Get("fields"), ","))
		cycles_s    = types.ArrayString(strings.Split(c.Params.Get("cycles"), ","))
		replica_cap = int(c.Params.Int64("replica_cap"))
		cycles      = types.ArrayUint64{}
	)

	defer c.RenderJson(&rsp)

	if !fields.Has("pod") &&
		!fields.Has("pod/cpu") &&
		!fields.Has("pod/mem") &&
		!fields.Has("pod/vol") {
		rsp.Error = types.NewErrorMeta("400", "Invalid fields")
		return
	}
	if replica_cap < 1 {
		replica_cap = 1
	} else if replica_cap > inapi.AppSpecExpDeployRepNumMax {
		replica_cap = inapi.AppSpecExpDeployRepNumMax
	}
	for _, v := range cycles_s {
		u64, _ := strconv.ParseUint(v, 10, 64)
		if u64 > 0 {
			cycles.Set(u64)
		}
	}
	if !cycles.Has(3600) &&
		!cycles.Has(86400) &&
		!cycles.Has(31*86400) {
		rsp.Error = types.NewErrorMeta("400", "Invalid cycles")
		return
	}

	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	if rs := in_db.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan", set.Plan)); rs.OK() {
		rs.Decode(&spec_plan)
	}
	if spec_plan.Meta.ID == "" || spec_plan.Meta.ID != set.Plan {
		rsp.Error = types.NewErrorMeta("400", "Spec Not Found")
		return
	}
	spec_plan.ChargeFix()

	//
	if err := set.Valid(spec_plan); err != nil {
		rsp.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	//
	var zone inapi.ResZone
	if rs := in_db.GlobalMaster.PvGet(inapi.NsGlobalSysZone(set.Zone)); rs.OK() {
		rs.Decode(&zone)
	}
	if zone.Meta.Id == "" {
		rsp.Error = types.NewErrorMeta("400", "Zone Not Found")
		return
	}

	//
	var cell inapi.ResCell
	if rs := in_db.GlobalMaster.PvGet(inapi.NsGlobalSysCell(set.Zone, set.Cell)); rs.OK() {
		rs.Decode(&cell)
	}
	if cell.Meta.Id == "" {
		rsp.Error = types.NewErrorMeta("400", "Cell Not Found")
		return
	}

	res_vol := spec_plan.ResVolume(set.ResVolume)
	if res_vol == nil {
		rsp.Error = types.NewErrorMeta("400", "No ResVolume Found")
		return
	}

	pod := inapi.Pod{
		Spec: &inapi.PodSpecBound{
			Zone: set.Zone,
			Cell: set.Cell,
			Volumes: []inapi.PodSpecResVolumeBound{
				{
					Ref: inapi.ObjectReference{
						Id:   res_vol.RefId,
						Name: res_vol.RefId,
						// Version: res_vol.Meta.Version,
					},
					Name:      "system",
					SizeLimit: set.ResVolumeSize,
				},
			},
		},
		Operate: inapi.PodOperate{
			ReplicaCap: replica_cap,
		},
	}

	//
	img := spec_plan.Image(set.Box.Image)
	if img == nil {
		rsp.Error = types.NewErrorMeta("400", "No Image Found")
		return
	}

	res := spec_plan.ResCompute(set.Box.ResCompute)
	if res == nil {
		rsp.Error = types.NewErrorMeta("400", "No ResCompute Found")
		return
	}

	pod.Spec.Box = inapi.PodSpecBoxBound{
		Name: set.Box.Name,
		Resources: &inapi.PodSpecBoxResComputeBound{
			Ref: &inapi.ObjectReference{
				Id:   res.RefId,
				Name: res.RefId,
				// Version: res.Meta.Version,
			},
			CpuLimit: res.CpuLimit,
			MemLimit: res.MemLimit,
		},
	}

	var (
		amount_cpu = float64(0)
		amount_mem = float64(0)
		amount_vol = float64(0)
		replicas   = float64(pod.Operate.ReplicaCap)
	)

	// Volumes
	for _, v := range pod.Spec.Volumes {
		amount_vol += iamapi.AccountFloat64Round(
			spec_plan.ResVolumeCharge.CapSize*float64(v.SizeLimit), 4)
	}

	if pod.Spec.Box.Resources != nil {
		// CPU
		amount_cpu += iamapi.AccountFloat64Round(
			spec_plan.ResComputeCharge.Cpu*(float64(pod.Spec.Box.Resources.CpuLimit)/10), 4)

		// RAM
		amount_mem += iamapi.AccountFloat64Round(
			spec_plan.ResComputeCharge.Mem*float64(pod.Spec.Box.Resources.MemLimit), 4)
	}

	amount_cpu = amount_cpu * replicas
	amount_mem = amount_mem * replicas
	amount_vol = amount_vol * replicas

	for _, ct := range cycles {

		if fields.Has("pod") {
			rsp.Items = append(rsp.Items, &inapi.PodEstimateEntry{
				Name:        "pod",
				CycleAmount: iamapi.AccountFloat64Round((amount_cpu+amount_mem+amount_vol)*(float64(ct)/3600), 2),
				CycleTime:   ct,
			})
		}

		if fields.Has("pod/cpu") {
			rsp.Items = append(rsp.Items, &inapi.PodEstimateEntry{
				Name:        "pod/cpu",
				CycleAmount: iamapi.AccountFloat64Round(amount_cpu*(float64(ct)/3600), 2),
				CycleTime:   ct,
			})
		}

		if fields.Has("pod/mem") {
			rsp.Items = append(rsp.Items, &inapi.PodEstimateEntry{
				Name:        "pod/mem",
				CycleAmount: iamapi.AccountFloat64Round(amount_mem*(float64(ct)/3600), 2),
				CycleTime:   ct,
			})
		}

		if fields.Has("pod/vol") {
			rsp.Items = append(rsp.Items, &inapi.PodEstimateEntry{
				Name:        "pod/vol",
				CycleAmount: iamapi.AccountFloat64Round(amount_vol*(float64(ct)/3600), 2),
				CycleTime:   ct,
			})
		}
	}

	rsp.Kind = "PodEstimate"
}
