// Copyright 2015 Authors, All rights reserved.
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

package zonemaster

import (
	"fmt"
	"math"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/lessos/loscore/data"
	"github.com/lessos/loscore/losapi"
	"github.com/lessos/loscore/status"
)

var (
	pod_spec_plans = []*losapi.PodSpecPlan{}
)

func pod_charge() error {

	if status.ZoneId == "" ||
		!status.ZoneHostListImported ||
		status.Zone == nil {
		return nil
	}

	// TODO
	pod_spec_plans = []*losapi.PodSpecPlan{}
	if rs := data.ZoneMaster.PvScan(losapi.NsGlobalPodSpec("plan", ""), "", "", 100); rs.OK() {
		rss := rs.KvList()
		for _, v := range rss {
			var item losapi.PodSpecPlan
			if err := v.Decode(&item); err == nil {
				item.ChargeFix()
				pod_spec_plans = append(pod_spec_plans, &item)
			}
		}
	}

	if len(pod_spec_plans) < 1 {
		hlog.Printf("info", "no pod spec plan found")
	}

	if rs := data.ZoneMaster.PvScan(
		losapi.NsZonePodInstance(status.ZoneId, ""), "", "", 1000); rs.OK() {

		pods := []losapi.Pod{}
		rss := rs.KvList()
		for _, v := range rss {
			var pod losapi.Pod
			if err := v.Decode(&pod); err == nil {
				pods = append(pods, pod)
			}
		}
		// hlog.Printf("info", "charging %d pods", len(pods))
		for _, pod := range pods {
			pod_charge_entry(pod)
		}
	}

	return nil
}

func pod_charge_entry(pod losapi.Pod) {

	if losapi.OpActionAllow(pod.Operate.Action, losapi.OpActionCharged) {
		return
	}

	if losapi.OpActionAllow(pod.Operate.Action, losapi.OpActionDestroy) &&
		pod.Payment != nil && pod.Payment.Payout > 0 {
		return
	}

	//
	if pod.Spec == nil || pod.Spec.Ref.Name == "" {
		return
	}
	var spec_plan *losapi.PodSpecPlan
	for _, v := range pod_spec_plans {
		if v.Meta.Name == pod.Spec.Ref.Name {
			spec_plan = v
			break
		}
	}
	if spec_plan == nil {
		return
	}

	//
	if n := len(pod.Operate.Replicas); n == 0 || n != pod.Operate.ReplicaCap {
		return
	}

	for _, v := range pod.Operate.Replicas {
		if v.Node == "" {
			return // TODO
		}
	}

	cycle_amount := float64(0)

	// Volumes
	for _, v := range pod.Spec.Volumes {
		// v.SizeLimit = 20 * losapi.ByteGB
		cycle_amount += spec_plan.ResourceVolumeCharge.CapSize * float64(v.SizeLimit/losapi.ByteMB)
	}

	for _, v := range pod.Spec.Boxes {

		if v.Resources != nil {
			// CPU
			// v.Resources.CpuLimit = 1000
			cycle_amount += spec_plan.ResourceComputeCharge.Cpu * (float64(v.Resources.CpuLimit) / 1000)

			// RAM
			// v.Resources.MemLimit = 1 * losapi.ByteGB
			cycle_amount += spec_plan.ResourceComputeCharge.Memory * float64(v.Resources.MemLimit/losapi.ByteMB)
		}
	}

	if pod.Payment == nil {
		pod.Payment = &losapi.PodPayment{
			TimeStart: uint32(time.Now().Unix()),
			TimeClose: 0,
			Prepay:    0,
			Payout:    0,
		}
		// hlog.Printf("info", "new pod.payment")
	}

	// close prev payment cycle
	if pod.Payment.Payout > 0 {
		pod.Payment.TimeStart = pod.Payment.TimeClose
		pod.Payment.TimeClose = 0
		pod.Payment.Prepay = 0
		pod.Payment.Payout = 0
	}

	if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		pod.Payment.TimeClose = iamapi.AccountChargeCycleTimeClose(
			iamapi.AccountChargeCycleMonth, pod.Payment.TimeStart+1)
	}

	if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		return
	}

	cycle_amount = cycle_amount * (float64(pod.Payment.TimeClose-pod.Payment.TimeStart) / 3600)
	cycle_amount = math.Trunc(cycle_amount*1e4+0.5) * 1e-4
	if cycle_amount < 0.0001 {
		cycle_amount = 0.0001
	}

	// hlog.Printf("info", "Pod %s AccountCharge AMOUNT %f", pod.Meta.ID, cycle_amount)

	time_close_now := iamapi.AccountChargeCycleTimeCloseNow(iamapi.AccountChargeCycleMonth)

	if pod.Payment.TimeClose == time_close_now && pod.Payment.Prepay == 0 {

		if rsp := iamclient.AccountChargePrepay(iamapi.AccountChargePrepay{
			User:      pod.Meta.User,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Prepay:    cycle_amount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
		}); rsp.Kind == "AccountChargePrepay" {
			pod.Payment.Prepay = cycle_amount
			data.ZoneMaster.PvPut(
				losapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
				pod,
				nil,
			)
			// hlog.Printf("info", "Pod %s AccountChargePrepay %f", pod.Meta.ID, pod.Payment.Prepay)
		} else {
			if rsp.Error != nil {
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					pod_entry_chargeout(pod.Meta.ID)
				}
				hlog.Printf("error", "Pod %s AccountChargePrepay %f %s",
					pod.Meta.ID, pod.Payment.Prepay, rsp.Error.Code+" : "+rsp.Error.Message)
			}
		}

	} else if pod.Payment.TimeClose < time_close_now && pod.Payment.Payout == 0 {

		if rsp := iamclient.AccountChargePayout(iamapi.AccountChargePayout{
			User:      pod.Meta.User,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Payout:    cycle_amount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
		}); rsp.Kind == "AccountChargePayout" {
			pod.Payment.Payout = cycle_amount
			data.ZoneMaster.PvPut(
				losapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
				pod,
				nil,
			)
			// hlog.Printf("info", "Pod %s AccountChargePayout %f", pod.Meta.ID, pod.Payment.Payout)
		} else {
			if rsp.Error != nil {
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					pod_entry_chargeout(pod.Meta.ID)
				}
				hlog.Printf("error", "Pod %s AccountChargePayout %f %s",
					pod.Meta.ID, pod.Payment.Payout, rsp.Error.Code+" : "+rsp.Error.Message)
			}
		}
	}
}

func pod_entry_chargeout(pod_id string) {

	var prev losapi.Pod
	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalPodInstance(pod_id)); !rs.OK() {
		return
	} else {
		rs.Decode(&prev)
	}

	if losapi.OpActionAllow(prev.Operate.Action, losapi.OpActionStop) {
		return
	}

	prev.Operate.Action = losapi.OpActionStop | losapi.OpActionCharged
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	data.ZoneMaster.PvPut(losapi.NsGlobalPodInstance(prev.Meta.ID), prev, nil)

	// Pod Map to Cell Queue
	qstr := losapi.NsZonePodOpQueue(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	data.ZoneMaster.PvPut(qstr, prev, nil)

	hlog.Printf("info", "Pod %s AccountChargeOut", prev.Meta.ID)
}
