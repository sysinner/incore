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

package zonemaster

import (
	"fmt"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	pod_spec_plans    = []*inapi.PodSpecPlan{}
	pod_charge_iam_ak = iamapi.AccessKey{
		User: "sysadmin",
	}
)

func pod_charge() error {

	if status.ZoneId == "" ||
		!status.ZoneHostListImported ||
		status.Zone == nil {
		return nil
	}

	if v, ok := status.Zone.OptionGet("iam/acc_charge/access_key"); !ok {
		return nil
	} else {
		pod_charge_iam_ak.AccessKey = v
	}

	if v, ok := status.Zone.OptionGet("iam/acc_charge/secret_key"); !ok {
		return nil
	} else {
		pod_charge_iam_ak.SecretKey = v
	}

	// TODO
	pod_spec_plans = []*inapi.PodSpecPlan{}
	if rs := data.ZoneMaster.PvScan(inapi.NsGlobalPodSpec("plan", ""), "", "", 100); rs.OK() {
		rss := rs.KvList()
		for _, v := range rss {
			var item inapi.PodSpecPlan
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
		inapi.NsZonePodInstance(status.ZoneId, ""), "", "", 1000); rs.OK() {

		pods := []inapi.Pod{}
		rss := rs.KvList()
		for _, v := range rss {
			var pod inapi.Pod
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

func pod_charge_entry(pod inapi.Pod) bool {

	if pod.Payment == nil {
		pod.Payment = &inapi.PodPayment{}
	}

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {

		if (pod.Payment.Payout > 0 && pod.Payment.TimeClose > pod.Payment.TimeStart) ||
			(pod.Payment.Payout == 0 && pod.Payment.Prepay == 0) {
			return false
		}
	}

	//
	if pod.Spec == nil || pod.Spec.Ref.Name == "" {
		return false
	}
	var spec_plan *inapi.PodSpecPlan
	for _, v := range pod_spec_plans {
		if v.Meta.Name == pod.Spec.Ref.Name {
			spec_plan = v
			break
		}
	}
	if spec_plan == nil {
		return false
	}

	inst_num := 0
	for _, v := range pod.Operate.Replicas {
		if v.Node != "" {
			inst_num++
		}
	}

	var (
		cycle_amount = float64(0)
		tn           = uint32(time.Now().Unix())
	)

	// Res Volumes
	for _, v := range pod.Spec.Volumes {
		// v.SizeLimit = 20 * inapi.ByteGB
		cycle_amount += iamapi.AccountFloat64Round(
			spec_plan.ResVolumeCharge.CapSize*float64(v.SizeLimit/inapi.ByteMB), 4)
	}

	// Res Computes
	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStart) {
		for _, v := range pod.Spec.Boxes {
			if v.Resources == nil {
				continue
			}
			// CPU v.Resources.CpuLimit = 1000
			cycle_amount += iamapi.AccountFloat64Round(
				spec_plan.ResComputeCharge.Cpu*(float64(v.Resources.CpuLimit)/1000), 4)

			// MEM v.Resources.MemLimit = 1 * inapi.ByteGB
			cycle_amount += iamapi.AccountFloat64Round(
				spec_plan.ResComputeCharge.Mem*float64(v.Resources.MemLimit/inapi.ByteMB), 4)
		}
	}

	if cycle_amount == 0 || inst_num == 0 {
		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			pod.Payment.TimeClose = tn
			data.ZoneMaster.PvPut(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
				pod,
				nil,
			)
		}
		return false
	}

	cycle_amount = iamapi.AccountFloat64Round(cycle_amount*float64(inst_num), 4)

	// close prev payment cycle
	if pod.Payment.Payout > 0 {
		pod.Payment.TimeStart = pod.Payment.TimeClose
		pod.Payment.TimeClose = 0
		pod.Payment.Prepay = 0
		pod.Payment.Payout = 0
	}

	if pod.Payment.TimeStart == 0 {
		pod.Payment.TimeStart = tn - 1
	}

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
		pod.Payment.TimeClose = tn
	} else if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		pod.Payment.TimeClose = iamapi.AccountChargeCycleTimeClose(
			iamapi.AccountChargeCycleMonth, pod.Payment.TimeStart+1)
	}

	if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		return false
	}

	if pod.Payment.CycleAmount == 0 || pod.Payment.CycleAmount == cycle_amount {
		pod.Payment.CycleAmount = cycle_amount
	}

	if pod.Payment.CycleAmount != cycle_amount {
		pod.Payment.TimeClose = iamapi.AccountChargeTimeNow()
		hlog.Printf("warn", "Pod %s AccountCharge CycleAmount Changed from %f to %f",
			pod.Meta.ID, pod.Payment.CycleAmount, cycle_amount)
	}

	pay_amount := pod.Payment.CycleAmount * (float64(pod.Payment.TimeClose-pod.Payment.TimeStart) / 3600)
	pay_amount = iamapi.AccountFloat64Round(pay_amount, 2)
	if pay_amount < 0.01 {
		pay_amount = 0.01
	}

	// hlog.Printf("info", "Pod %s AccountCharge AMOUNT %f, NUM: %d", pod.Meta.ID, pay_amount, inst_num)

	time_close_now := iamapi.AccountChargeCycleTimeCloseNow(iamapi.AccountChargeCycleMonth)

	if pod.Payment.TimeClose == time_close_now && pod.Payment.Prepay == 0 {

		// hlog.Printf("info", "Pod %s AccountChargePrepay %f %d %d",
		// 	pod.Meta.ID, pay_amount,
		// 	pod.Payment.TimeStart, pod.Payment.TimeClose)

		if rsp := iamclient.AccountChargePrepay(iamapi.AccountChargePrepay{
			User:      pod.Meta.User,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Prepay:    pay_amount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
		}, pod_charge_iam_ak); rsp.Kind == "AccountChargePrepay" {
			pod.Payment.Prepay = pay_amount
			pod.Payment.CycleAmount = cycle_amount
			data.ZoneMaster.PvPut(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
				pod,
				nil,
			)
			// hlog.Printf("info", "Pod %s AccountChargePrepay %f", pod.Meta.ID, pod.Payment.Prepay)
		} else {
			if rsp.Error != nil {
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					pod_entry_chargeout(pod.Meta.ID)
					//
					pod.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(pod.Operate.OpLog,
						inapi.NewPbOpLogEntry(oplog_zms_charge, inapi.PbOpLogWarn, rsp.Error.Message))

					data.ZoneMaster.PvPut(
						inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
						pod,
						nil,
					)
				}
				hlog.Printf("error", "Pod %s AccountChargePrepay %f %s",
					pod.Meta.ID, pod.Payment.Prepay, rsp.Error.Code+" : "+rsp.Error.Message)
			}
		}

	} else if pod.Payment.TimeClose < time_close_now && pod.Payment.Payout == 0 {

		// hlog.Printf("error", "Pod %s AccountChargePayout %f %d %d",
		// 	pod.Meta.ID, pod.Payment.Payout, pod.Payment.TimeStart, pod.Payment.TimeClose)

		if rsp := iamclient.AccountChargePayout(iamapi.AccountChargePayout{
			User:      pod.Meta.User,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Payout:    pay_amount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
		}, pod_charge_iam_ak); rsp.Kind == "AccountChargePayout" {
			pod.Payment.Payout = pay_amount
			pod.Payment.CycleAmount = cycle_amount
			data.ZoneMaster.PvPut(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
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
	} else {
		// hlog.Printf("info", "Pod %s AccountCharge SKIP", pod.Meta.ID)
	}

	return false
}

func pod_entry_chargeout(pod_id string) {

	var prev inapi.Pod
	if rs := data.ZoneMaster.PvGet(inapi.NsZonePodInstance(status.ZoneId, pod_id)); !rs.OK() {
		return
	} else {
		rs.Decode(&prev)
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStop) {
		return
	}

	prev.Operate.Action = inapi.OpActionStop
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, prev.Meta.ID), prev, nil)

	// Pod Map to Cell Queue
	qstr := inapi.NsZonePodOpQueue(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	data.ZoneMaster.PvPut(qstr, prev, nil)

	hlog.Printf("info", "Pod %s AccountChargeOut", prev.Meta.ID)
}
