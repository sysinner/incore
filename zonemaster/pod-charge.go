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
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	inCfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	pod_specPlans = []*inapi.PodSpecPlan{}
)

func podChargeRefresh() error {

	if status.ZoneId == "" ||
		!status.ZoneHostListImported ||
		status.Zone == nil {
		return nil
	}

	if inCfg.Config.ZoneMain.IamAccessKey == nil {
		hlog.Printf("warn", "charge AccessKey not found")
		return nil
	}

	// TODO
	pod_specPlans = []*inapi.PodSpecPlan{}
	if rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalPodSpec("plan", ""), inapi.NsGlobalPodSpec("plan", "")).
		LimitNumSet(100).Query(); rs.OK() {
		for _, v := range rs.Items {
			var item inapi.PodSpecPlan
			if err := v.Decode(&item); err == nil {
				item.ChargeFix()
				pod_specPlans = append(pod_specPlans, &item)
			}
		}
	}

	if len(pod_specPlans) < 1 {
		hlog.Printf("info", "no pod spec plan found")
	}

	for _, pod := range status.ZonePodList.Items {
		podItemCharge(pod)
	}

	return nil
}

func podItemCharge(pod *inapi.Pod) bool {

	if pod.Payment == nil {
		pod.Payment = &inapi.PodPayment{}
	}

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {

		if (pod.Payment.Payout > 0 && pod.Payment.TimeClose > pod.Payment.TimeStart) ||
			(pod.Payment.Payout == 0 && pod.Payment.Prepay == 0) {
			return false
		}
	}

	//
	if pod.Spec == nil ||
		pod.Spec.Ref.Name == "" ||
		pod.Spec.VolSys == nil {
		return false
	}
	var specPlan *inapi.PodSpecPlan
	for _, v := range pod_specPlans {
		if v.Meta.Name == pod.Spec.Ref.Name {
			specPlan = v
			break
		}
	}
	if specPlan == nil {
		return false
	}

	var (
		cav    = float64(0)
		cac    = float64(0)
		cam    = float64(0)
		volv   = specPlan.VolCharge(pod.Spec.VolSys.RefId)
		repNum = 0
	)

	for _, v := range pod.Operate.Replicas {

		if v.Node == "" ||
			inapi.OpActionAllow(v.Action, inapi.OpActionDestroy) {
			continue
		}

		if inapi.OpActionAllow(v.Action, inapi.OpActionStart) {

			// CPU in cores, 1 = .1 cores
			cac += iamapi.AccountFloat64Round(
				specPlan.ResComputeCharge.Cpu*(float64(v.ResCpu)/10), 4)

			// MEM in ByteMB
			cam += iamapi.AccountFloat64Round(
				specPlan.ResComputeCharge.Mem*float64(v.ResMem), 4)
		}

		// Volume
		cav += iamapi.AccountFloat64Round(volv*float64(v.VolSys), 4)

		repNum += 1
	}

	var (
		cycleAmount = cac + cam + cav
		comments    = []string{
			fmt.Sprintf("CPU %.4f", cac),
			fmt.Sprintf("RAM %.4f", cam),
			fmt.Sprintf("VOL %.4f", cav),
			fmt.Sprintf("REP %d", repNum),
		}
		tn = uint32(time.Now().Unix())
	)

	if cycleAmount == 0 || repNum == 0 {
		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
			pod.Payment.TimeClose = tn
			data.DataZone.NewWriter(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod).Commit()
		}
		return false
	}

	cycleAmount = iamapi.AccountFloat64Round(cycleAmount, 4)

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

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
		pod.Payment.TimeClose = tn
	} else if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		pod.Payment.TimeClose = iamapi.AccountChargeCycleTimeClose(
			iamapi.AccountChargeCycleMonth, pod.Payment.TimeStart+1)
	}

	if pod.Payment.TimeClose <= pod.Payment.TimeStart {
		return false
	}

	if pod.Payment.CycleAmount == 0 || pod.Payment.CycleAmount == cycleAmount {
		pod.Payment.CycleAmount = cycleAmount
	}

	if pod.Payment.CycleAmount != cycleAmount {
		pod.Payment.TimeClose = iamapi.AccountChargeTimeNow()
		hlog.Printf("warn", "Pod %s AccountCharge CycleAmount Changed from %f to %f",
			pod.Meta.ID, pod.Payment.CycleAmount, cycleAmount)
	}

	payUser := pod.Meta.User
	if pod.Payment.User != "" && pod.Payment.User != payUser {
		payUser = pod.Payment.User
		pod.Payment.TimeClose = tn
	}

	payAmount := pod.Payment.CycleAmount * (float64(pod.Payment.TimeClose-pod.Payment.TimeStart) / 3600)
	payAmount = iamapi.AccountFloat64Round(payAmount, 2)
	if payAmount < 0.01 {
		payAmount = 0.01
	}

	// hlog.Printf("info", "Pod %s AccountCharge AMOUNT %f, NUM: %d", pod.Meta.ID, payAmount, repNum)

	timeCloseNow := iamapi.AccountChargeCycleTimeCloseNow(iamapi.AccountChargeCycleMonth)

	if pod.Payment.TimeClose == timeCloseNow && pod.Payment.Prepay == 0 {

		// hlog.Printf("info", "Pod %s AccountChargePrepay %f %d %d",
		// 	pod.Meta.ID, payAmount,
		// 	pod.Payment.TimeStart, pod.Payment.TimeClose)

		if rsp := iamclient.AccountChargePrepay(iamapi.AccountChargePrepay{
			User:      payUser,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Prepay:    payAmount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
			Comment:   strings.Join(comments, ", "),
		}, inCfg.Config.ZoneMain.IamAccessKey); rsp.Kind == "AccountChargePrepay" {
			pod.Payment.Prepay = payAmount
			pod.Payment.CycleAmount = cycleAmount
			pod.Payment.User = ""
			data.DataZone.NewWriter(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod).Commit()
		} else {
			if rsp.Error != nil {
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					podEntryChargeOut(pod.Meta.ID)
					//
					pod.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(pod.Operate.OpLog,
						inapi.NewPbOpLogEntry(inapi.OpLogNsZoneMasterPodScheduleCharge, inapi.PbOpLogWarn, rsp.Error.Message))

					data.DataZone.NewWriter(
						inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod).Commit()
				}
				hlog.Printf("error", "Pod %s AccountChargePrepay %f %s",
					pod.Meta.ID, pod.Payment.Prepay, rsp.Error.Code+" : "+rsp.Error.Message)
			}
		}

	} else if pod.Payment.TimeClose < timeCloseNow && pod.Payment.Payout == 0 {

		// hlog.Printf("error", "Pod %s AccountChargePayout %f %d %d",
		// 	pod.Meta.ID, pod.Payment.Payout, pod.Payment.TimeStart, pod.Payment.TimeClose)

		if rsp := iamclient.AccountChargePayout(iamapi.AccountChargePayout{
			User:      payUser,
			Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", pod.Meta.ID)),
			Payout:    payAmount,
			TimeStart: pod.Payment.TimeStart,
			TimeClose: pod.Payment.TimeClose,
			Comment:   strings.Join(comments, ", "),
		}, inCfg.Config.ZoneMain.IamAccessKey); rsp.Kind == "AccountChargePayout" {
			pod.Payment.Payout = payAmount
			pod.Payment.CycleAmount = cycleAmount
			pod.Payment.User = ""
			data.DataZone.NewWriter(
				inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod).Commit()
		} else {
			if rsp.Error != nil {
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					podEntryChargeOut(pod.Meta.ID)
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

func podEntryChargeOut(pod_id string) {

	prev := status.ZonePodList.Items.Get(pod_id)
	if prev == nil {
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionStop) {
		return
	}

	prev.Operate.Action = inapi.OpActionStop
	prev.Operate.Version++
	prev.Meta.Updated = types.MetaTimeNow()

	data.DataZone.NewWriter(inapi.NsZonePodInstance(status.ZoneId, prev.Meta.ID), prev).Commit()

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	data.DataGlobal.NewWriter(sqkey, prev).Commit()

	hlog.Printf("info", "Pod %s AccountChargeOut", prev.Meta.ID)
}
