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
	"errors"
	"fmt"
	"strings"
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
	Scheduler             inapi.Scheduler
	pod_ops               = map[string]*inapi.PodOperate{}
	server_error          = errors.New("server error")
	zonePodSpecPlans      inapi.PodSpecPlanList
	pod_res_free_time_min uint32 = 60
)

const (
	oplog_zms         = "zone-master/scheduler"
	oplog_zms_destroy = "zone-master/scheduler/destroy"
	oplog_zms_charge  = "zone-master/scheduler/charge"
)

type host_res_usage struct {
	cpu   int64
	mem   int64
	ports types.ArrayUint32
}

func scheduler_exec() error {

	if status.ZoneId == "" ||
		!status.ZoneHostListImported ||
		status.Zone == nil {
		return nil
	}

	if Scheduler == nil {
		return errors.New("No Scheduler Found")
	}

	//
	zonePodSpecPlans.Items = []*inapi.PodSpecPlan{}
	rss := data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("plan", ""), "", "", 1000).KvList()
	for _, v := range rss {
		var spec_plan inapi.PodSpecPlan
		if err := v.Decode(&spec_plan); err == nil {
			spec_plan.ChargeFix()
			zonePodSpecPlans.Items = append(zonePodSpecPlans.Items, &spec_plan)
		}
	}
	if len(zonePodSpecPlans.Items) < 1 {
		return errors.New("No PodSpecPlan Found")
	}

	//
	var (
		tn              = uint32(time.Now().Unix())
		host_res_usages = map[string]*host_res_usage{}
	)
	rss = data.ZoneMaster.PvScan(
		inapi.NsZonePodInstance(status.ZoneId, ""), "", "", 10000).KvList()
	for _, v := range rss {
		var pod inapi.Pod
		if err := v.Decode(&pod); err != nil {
			return err
		}
		status.ZonePodList.Set(&pod)

		if scheduler_status_refresh(&pod) {
			data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod, nil)
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			if uint32(time.Now().Unix())-pod.Operate.Operated > inapi.PodDestroyTTL {
				if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstanceDestroy(status.ZoneId, pod.Meta.ID), pod, nil); rs.OK() {
					data.ZoneMaster.PvDel(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), nil)
					hlog.Printf("warn", "zone-master/pod/backup:%s", pod.Meta.ID)
				}
			}
			continue
		}

		// TODO
		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStop|inapi.OpActionStopped) &&
			!inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionResFree) &&
			tn-pod.Operate.Operated > pod_res_free_time_min {

			pod.Operate.Action = pod.Operate.Action | inapi.OpActionResFree
			//
			if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod, nil); !rs.OK() {
				return errors.New(rs.Bytex().String())
			}
			hlog.Printf("warn", "zone-master/pod/stopped %s, SKIP ResMerge", pod.Meta.ID)
		}

		spec_res := pod.Spec.ResComputeBound()
		for _, rp := range pod.Operate.Replicas {
			if rp.Node == "" {
				continue
			}

			hres, ok := host_res_usages[rp.Node]
			if !ok {
				hres = &host_res_usage{}
			}

			if !inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionResFree) {
				hres.cpu += spec_res.CpuLimit
				hres.mem += spec_res.MemLimit
			}

			for _, rpp := range rp.Ports {
				if rpp.HostPort > 0 {
					hres.ports.Set(uint32(rpp.HostPort))
				}
			}

			host_res_usages[rp.Node] = hres
		}

		// fmt.Println("pod", pod.Meta.ID, pod.Meta.User, spec_res.CpuLimit, spec_res.MemLimit,
		//	pod.Operate.Action, strings.Join(inapi.OpActionStrings(pod.Operate.Action), ","))
	}

	for _, host := range status.ZoneHostList.Items {

		var (
			res, ok = host_res_usages[host.Meta.Id]
			sync    = false
		)

		if !ok {
			if host.Operate.CpuUsed > 0 {
				host.Operate.CpuUsed, sync = 0, true
			}
			if host.Operate.MemUsed > 0 {
				host.Operate.MemUsed, sync = 0, true
			}
			if len(host.Operate.PortUsed) > 0 {
				host.Operate.PortUsed, sync = []uint32{}, true
			}
		} else {
			if host.Operate.CpuUsed != res.cpu {
				host.Operate.CpuUsed, sync = res.cpu, true
			}
			if host.Operate.MemUsed != res.mem {
				host.Operate.MemUsed, sync = res.mem, true
			}
			if !res.ports.Equal(host.Operate.PortUsed) {
				host.Operate.PortUsed, sync = res.ports, true
			}
		}

		if sync {

			host.OpPortSort()

			if rs := data.ZoneMaster.PvPut(
				inapi.NsZoneSysHost(status.ZoneId, host.Meta.Id), host, nil,
			); !rs.OK() {
				return fmt.Errorf("host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String())
			}
		}
	}

	//
	for _, cell := range status.Zone.Cells {
		scheduler_exec_cell(cell.Meta.Id)
	}

	return nil
}

func scheduler_status_refresh(pod *inapi.Pod) bool {

	pod.Operate.Action = inapi.OpActionControlFilter(pod.Operate.Action)

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStart) ||
		inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStop|inapi.OpActionStopped) ||
		inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
		return false
	}

	rs := data.ZoneMaster.PvScan(
		inapi.NsZonePodReplicaStatus(status.ZoneId, "", 0),
		pod.Meta.ID,
		pod.Meta.ID+".zzzz",
		10000)
	if !rs.OK() {
		return false
	}

	rss := rs.KvList()
	action := uint32(0)
	for _, v := range rss {

		var pr_status inapi.PbPodRepStatus
		if err := v.Decode(&pr_status); err != nil {
			continue
		}

		if !inapi.OpActionAllow(pr_status.Action, inapi.OpActionStopped) &&
			!inapi.OpActionAllow(pr_status.Action, inapi.OpActionDestroyed) {
			continue
		}

		if action == 0 {
			action = pr_status.Action
		}

		if action != pr_status.Action {
			return false
		}
	}

	if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) &&
		((action == 0 && len(rss) == 0) || action == inapi.OpActionDestroyed) &&
		uint32(time.Now().Unix())-pod.Operate.Operated > 3600 {
		action = inapi.OpActionDestroyed
	} else if action == 0 {
		return false
	}

	hlog.Printf("info", "zone-master/status-refresh pod:%s, rep:%d, rep-action:%d, action:%s",
		pod.Meta.ID, len(pod.Operate.Replicas), len(rss), strings.Join(inapi.OpActionStrings(action), ","),
	)

	pod.Operate.Action = pod.Operate.Action | action

	return true
}

func scheduler_exec_cell(cell_id string) {

	// TODO pager
	rss := data.GlobalMaster.PvScan(
		inapi.NsGlobalSetQueuePod(status.ZoneId, cell_id, ""), "", "", 10000).KvList()
	if len(rss) == 0 {
		return
	}

	start := time.Now()
	for _, v := range rss {
		var podq inapi.Pod
		err := v.Decode(&podq)
		if err != nil {
			hlog.Printf("error", "invalid data struct: %s", err.Error())
			continue
		}

		if podq.Spec == nil || podq.Spec.Cell != cell_id {
			hlog.Printf("error", "invalid data struct: no spec/cell found")
			continue
		}

		err = scheduler_exec_pod(&podq)
		if err != nil && err.Error() != "" {
			hlog.Print("error", err.Error())
		}

		// fmt.Println("scheduler_exec_pod", podq.Meta.ID, inapi.OpActionStrings(podq.Operate.Action))
		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			continue
		}

		if err == nil {
			data.GlobalMaster.PvDel(inapi.NsGlobalSetQueuePod(status.ZoneId, podq.Spec.Cell, podq.Meta.ID), nil)
		}
	}
	hlog.Printf("debug", "scheduling %d pods in %v", len(rss), time.Since(start))
}

func scheduler_exec_pod(podq *inapi.Pod) error {

	// hlog.Printf("error", "exec podq #%s instance", podq.Meta.ID)

	var (
		start = time.Now()
		prev  inapi.Pod
	)

	if rs := data.ZoneMaster.PvGet(
		inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID),
	); rs.OK() {

		if err := rs.Decode(&prev); err != nil {
			hlog.Printf("error", "bad prev podq #%s instance", podq.Meta.ID)
			// TODO error log
			return fmt.Errorf("bad prev podq #%s instance", podq.Meta.ID)
		}

	} else if !rs.NotFound() {
		return fmt.Errorf("failed on get podq #%s, err: %s", podq.Meta.ID, rs.Bytex().String())
	}

	// fmt.Println("status", podq.Meta.ID, inapi.OpActionStrings(podq.Operate.Action),
	// 	inapi.OpActionStrings(prev.Operate.Action))

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionResFree) {
		podq.Operate.Action = podq.Operate.Action | inapi.OpActionResFree
	}

	if len(prev.Operate.Replicas) > 0 {
		podq.Operate.Replicas = prev.Operate.Replicas
	} else {
		podq.Operate.Replicas.CapacitySet(podq.Operate.ReplicaCap)
	}

	if podq.Operate.Version == prev.Operate.Version {
		for _, v := range prev.Operate.OpLog {
			podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog, v)
		}
	}

	if prev.Payment != nil {
		podq.Payment = prev.Payment
	}

	if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionDestroy) {
		return scheduler_exec_pod_destroy(podq)
	}

	if !podq.Operate.Replicas.InitScheduled() {

		//
		{
			spec_plan := zonePodSpecPlans.Get(podq.Spec.Ref.Id)
			if spec_plan == nil {
				return fmt.Errorf("bad pod.Spec #%s", podq.Meta.ID)
			}

			charge_amount := float64(0)

			// Volumes
			for _, v := range podq.Spec.Volumes {
				charge_amount += iamapi.AccountFloat64Round(
					spec_plan.ResVolumeCharge.CapSize*float64(v.SizeLimit/inapi.ByteMB), 4)
			}

			for _, v := range podq.Spec.Boxes {

				if v.Resources != nil {
					// CPU
					charge_amount += iamapi.AccountFloat64Round(
						spec_plan.ResComputeCharge.Cpu*(float64(v.Resources.CpuLimit)/1000), 4)

					// RAM
					charge_amount += iamapi.AccountFloat64Round(
						spec_plan.ResComputeCharge.Mem*float64(v.Resources.MemLimit/inapi.ByteMB), 4)
				}
			}

			charge_amount = charge_amount * float64(podq.Operate.ReplicaCap)

			charge_cycle_min := float64(3600)
			charge_amount = iamapi.AccountFloat64Round(charge_amount*(charge_cycle_min/3600), 2)
			if charge_amount < 0.01 {
				charge_amount = 0.01
			}

			tnu := uint32(time.Now().Unix())
			if rsp := iamclient.AccountChargePreValid(iamapi.AccountChargePrepay{
				User:      podq.Meta.User,
				Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", podq.Meta.ID)),
				Prepay:    charge_amount,
				TimeStart: tnu,
				TimeClose: tnu + uint32(charge_cycle_min),
			}, status.ZonePodChargeAccessKey()); rsp.Error != nil {

				status, msg := inapi.PbOpLogWarn, rsp.Error.Message
				if msg == "" {
					msg = "Error Code: " + rsp.Error.Code
				}
				if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
					status = inapi.PbOpLogError
				}
				podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
					inapi.NewPbOpLogEntry(oplog_zms_charge, status, msg),
				)
				return errors.New("")
			} else if rsp.Kind != "AccountCharge" {
				return errors.New("Network Error")
			}

			podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
				inapi.NewPbOpLogEntry(oplog_zms_charge, inapi.PbOpLogOK, "PreValid OK"),
			)
		}

		//
		host_ids, err := Scheduler.ScheduleSets(*podq, status.ZoneHostList)
		if err != nil || len(host_ids) < len(podq.Operate.Replicas) {
			podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
				inapi.NewPbOpLogEntry(oplog_zms, inapi.PbOpLogWarn, "no available host resources (New), waiting"))
			return errors.New("")
		}

	} else if prev.Spec != nil {

		var (
			spec_res   = podq.Spec.ResComputeBound()
			spec_res_p = prev.Spec.ResComputeBound()
			p_res_cpu  = spec_res_p.CpuLimit
			p_res_mem  = spec_res_p.MemLimit
		)

		if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionResFree) {
			p_res_cpu, p_res_mem = 0, 0
		}

		if spec_res.CpuLimit > p_res_cpu ||
			spec_res.MemLimit > p_res_mem {

			cpu_fix := spec_res.CpuLimit - p_res_cpu
			mem_fix := spec_res.MemLimit - p_res_mem

			for _, oprep := range podq.Operate.Replicas {
				if oprep.Node == "" {
					continue
				}

				host := status.ZoneHostList.Item(oprep.Node)
				if host == nil || host.Operate == nil || host.Spec == nil || host.Spec.Capacity == nil {
					podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
						inapi.NewPbOpLogEntry(oplog_zms, inapi.PbOpLogWarn,
							"no available host resources (Spec/Action Changed), waiting"))
					return errors.New("")
				}

				if err := Scheduler.ScheduleHostValid(inapi.ScheduleEntry{
					Cpu: cpu_fix,
					Mem: mem_fix,
				}, host); err != nil {
					podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
						inapi.NewPbOpLogEntry(oplog_zms, inapi.PbOpLogWarn,
							"no available host resources (Spec/Action Changed), waiting"))
					return errors.New("")
				}
			}
		}
	}

	exec_ok := 0

	for _, oprep := range podq.Operate.Replicas {

		oplog := scheduler_exec_pod_rep(&prev, podq, oprep)
		if oplog.Status == inapi.PbOpLogOK {
			exec_ok++
		}

		//
		prs_path := inapi.NsZonePodReplicaStatus(
			status.ZoneId,
			podq.Meta.ID,
			oprep.Id,
		)
		prs := inapi.PbPodRepStatusSliceGet(status.ZonePodRepStatusSets,
			podq.Meta.ID, uint32(oprep.Id))
		if prs == nil {
			if rs := data.ZoneMaster.PvGet(prs_path); rs.OK() {
				rs.Decode(prs)
			}
		}
		if prs == nil || prs.Id != podq.Meta.ID {
			prs = &inapi.PbPodRepStatus{
				Id:  podq.Meta.ID,
				Rep: uint32(oprep.Id),
			}
		}

		prs.OpLog = inapi.NewPbOpLogSets(podq.OpRepKey(), podq.Operate.Version)
		prs.OpLog.LogSet(
			podq.Operate.Version,
			oplog_zms,
			oplog.Status, oplog.Message,
		)

		changed := false
		status.ZonePodRepStatusSets, changed = inapi.PbPodRepStatusSliceSync(
			status.ZonePodRepStatusSets, prs,
		)
		if changed {
			if rs := data.ZoneMaster.PvPut(prs_path, prs, nil); !rs.OK() {
				hlog.Printf("error", "zone/pod-rep-status saved %s, err (%s)", podq.OpRepKey(), rs.Bytex().String())
			}
		}
	}

	msg := fmt.Sprintf("scheduling %d/%d replica sets in %v", exec_ok, len(podq.Operate.Replicas), time.Since(start))

	if exec_ok != len(podq.Operate.Replicas) {
		podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
			podq.Operate.OpLog,
			inapi.NewPbOpLogEntry(oplog_zms, inapi.PbOpLogWarn, msg),
		)
		return errors.New("")
	}

	podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
		podq.Operate.OpLog,
		inapi.NewPbOpLogEntry(oplog_zms, inapi.PbOpLogOK, msg),
	)

	if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionResFree) &&
		!inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionStop) {
		podq.Operate.Action = inapi.OpActionRemove(podq.Operate.Action, inapi.OpActionResFree)
	}

	return nil
}

func scheduler_exec_pod_destroy(podq *inapi.Pod) error {

	start := time.Now()
	del_num := 0

	hlog.Printf("info", "destroy pod/%s, version:%d", podq.Meta.ID, podq.Operate.Version)

	for _, oprep := range podq.Operate.Replicas {

		if oprep.Node != "" {
			bdk := inapi.NsZoneHostBoundPod(status.ZoneId, oprep.Node, podq.Meta.ID, oprep.Id)
			if rs := data.ZoneMaster.PvGet(bdk); rs.OK() {
				var pod_bound inapi.Pod
				if err := rs.Decode(&pod_bound); err == nil && pod_bound.Meta.ID == podq.Meta.ID {
					if !inapi.OpActionAllow(pod_bound.Operate.Action, inapi.OpActionDestroy) {

						pod_bound.Operate.Action = inapi.OpActionDestroy
						pod_bound.Operate.Version = podq.Operate.Version

						del_num += 1

						data.ZoneMaster.PvPut(bdk, pod_bound, nil)
						hlog.Printf("info", "destroy pod/%s-%d action:%s",
							podq.Meta.ID, oprep.Id, strings.Join(inapi.OpActionStrings(podq.Operate.Action), ","))
					}
				}
			}
		} else {
			del_num += 1
		}

		//
		prs_path := inapi.NsZonePodReplicaStatus(
			status.ZoneId,
			podq.Meta.ID,
			oprep.Id,
		)
		prs := inapi.PbPodRepStatusSliceGet(status.ZonePodRepStatusSets,
			podq.Meta.ID, uint32(oprep.Id))
		if prs == nil {
			if rs := data.ZoneMaster.PvGet(prs_path); rs.OK() {
				rs.Decode(prs)
			}
		}
		if prs == nil || prs.Id != podq.Meta.ID {
			prs = &inapi.PbPodRepStatus{
				Id:  podq.Meta.ID,
				Rep: uint32(oprep.Id),
			}
		}

		prs.OpLog = inapi.NewPbOpLogSets(podq.OpRepKey(), podq.Operate.Version)
		prs.OpLog.LogSet(
			podq.Operate.Version,
			oplog_zms_destroy,
			inapi.PbOpLogInfo, "Sync Destroy",
		)

		prs.Action = podq.Operate.Action
		status.ZonePodRepStatusSets, _ = inapi.PbPodRepStatusSliceSync(
			status.ZonePodRepStatusSets, prs,
		)
		if rs := data.ZoneMaster.PvPut(prs_path, prs, nil); !rs.OK() {
			hlog.Printf("error", "zone/pod-rep-status saved %s, err (%s)", podq.OpRepKey(), rs.Bytex().String())
		}
	}

	msg := fmt.Sprintf("scheduling %d replica sets in %v", len(podq.Operate.Replicas), time.Since(start))

	podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
		podq.Operate.OpLog,
		inapi.NewPbOpLogEntry(oplog_zms_destroy, inapi.PbOpLogInfo, msg),
	)

	if del_num >= len(podq.Operate.Replicas) {
		podq.Operate.Action = podq.Operate.Action | inapi.OpActionDestroyed
	}

	if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionResFree) {
		podq.Operate.Action = inapi.OpActionRemove(podq.Operate.Action, inapi.OpActionResFree)
	}

	return nil
}

func scheduler_exec_pod_rep(prev, podq *inapi.Pod, oprep *inapi.PodOperateReplica) *inapi.PbOpLogEntry {

	var (
		host      *inapi.ResHost
		host_sync = false
	)

	if oprep.Node == "" {

		host_id, err := Scheduler.Schedule(*podq, status.ZoneHostList)

		if err != nil || host_id == "" {
			// TODO error log
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn, "no available host resources")
		}

		host = status.ZoneHostList.Item(host_id)
		if host == nil {
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn, "no available host resources")
		}

		podq.Operate.Replicas.Set(inapi.PodOperateReplica{
			Id:   oprep.Id,
			Node: host_id,
		})

		res := podq.Spec.ResComputeBound()
		host.SyncOpCpu(res.CpuLimit)
		host.SyncOpMem(res.MemLimit)

		host_sync = true

		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn, "Data IO error")
		}

		hlog.Printf("info", "schedule podq #%s on to host #%s (new)", podq.Meta.ID, host_id)
	} else {

		host = status.ZoneHostList.Item(oprep.Node)
		if host == nil {
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn, "no available host resources")
		}

		var (
			res   = podq.Spec.ResComputeBound()
			res_p = prev.Spec.ResComputeBound()
		)

		if res.CpuLimit != res_p.CpuLimit ||
			res.MemLimit != res_p.MemLimit {

			host.SyncOpCpu(res.CpuLimit - res_p.CpuLimit)
			host.SyncOpMem(res.MemLimit - res_p.MemLimit)

			host_sync = true
		}
	}

	var (
		host_peer_lan  = inapi.HostNodeAddress(host.Spec.PeerLanAddr)
		host_peer_port = host_peer_lan.Port()
		ports          = podq.AppServicePorts()
	)

	for i, pv := range ports {

		if pv.HostPort > 0 {

			if pv.HostPort == host_peer_port {

				ports[i].HostPort = 0

				hlog.Printf("warn", "the host port %s:%d already in use ",
					host.Spec.PeerLanAddr, pv.HostPort)

			} else if host.OpPortHas(pv.HostPort) {

				if ppv := oprep.Ports.Get(pv.BoxPort); ppv == nil ||
					ppv.HostPort != pv.HostPort {

					ports[i].HostPort = 0

					hlog.Printf("warn", "the host port %s:%d is already allocated",
						host.Spec.PeerLanAddr, pv.HostPort)
				}
			} else {
				host.OpPortAlloc(pv.HostPort)
				host_sync = true
			}

			continue
		}

		for _, pvp := range oprep.Ports {

			if pvp.BoxPort != pv.BoxPort {
				continue
			}

			if pvp.HostPort > 0 {
				ports.Sync(*pvp)
			}

			break
		}
	}

	// TODO delete unused port

	//
	ports_alloc := []uint16{}
	for i, p := range ports {

		if p.HostPort > 0 {
			continue
		}

		if port_alloc := host.OpPortAlloc(0); port_alloc > 0 {

			ports[i].HostPort = port_alloc
			host_sync = true
			ports_alloc = append(ports_alloc, port_alloc)

			hlog.Printf("info", "new port alloc to %s:%d",
				host.Spec.PeerLanAddr, port_alloc)

		} else {
			hlog.Printf("warn", "host #%s res-port out range", host.Meta.Id)
		}
	}

	//
	if len(ports) > 0 {

		var nsz inapi.NsPodServiceMap

		if rs := data.ZoneMaster.PvGet(inapi.NsZonePodServiceMap(podq.Meta.ID)); rs.OK() {
			rs.Decode(&nsz)
		}

		if nsz.User == "" {
			nsz.User = podq.Meta.User
		}
		if nsz.Id == "" {
			nsz.Id = podq.Meta.ID
		}

		changed := false

		for _, popv := range ports {

			if nsz.Sync(&inapi.NsPodServiceMap{
				Id:   podq.Meta.ID,
				User: podq.Meta.User,
				Services: []*inapi.NsPodServiceEntry{
					{
						Port: uint32(popv.BoxPort),
						Items: []*inapi.NsPodServiceHost{
							{
								Rep:  uint32(oprep.Id),
								Ip:   host_peer_lan.IP(),
								Port: uint32(popv.HostPort),
							},
						},
					},
				},
			}) {
				changed = true
			}

			// } popv.BoxPort, oprep.Id, host_peer_lan.IP(), popv.HostPort) {
			// 	changed = true
			// }
		}

		if changed {
			nsz.Updated = uint64(types.MetaTimeNow())
			data.ZoneMaster.PvPut(inapi.NsZonePodServiceMap(podq.Meta.ID), nsz, nil)
		}
	}

	oprep.Ports = ports

	if host_sync {

		hlog.Printf("info", "host #%s sync changes", host.Meta.Id)

		host.OpPortSort()

		if rs := data.ZoneMaster.PvPut(
			inapi.NsZoneSysHost(status.ZoneId, host.Meta.Id), host, nil,
		); !rs.OK() {
			hlog.Printf("error", "host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String())
			for _, pa := range ports_alloc {
				host.OpPortFree(pa)
			}
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn,
				fmt.Sprintf("host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String()))
		}

		// TODO
	}

	podq.Operate.Replica = oprep
	k := inapi.NsZoneHostBoundPod(status.ZoneId, oprep.Node, podq.Meta.ID, oprep.Id)

	if rs := data.ZoneMaster.PvPut(k, podq, nil); !rs.OK() {
		hlog.Printf("error", "zone/podq saved %s, err (%s)", k, rs.Bytex().String())
		return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn,
			fmt.Sprintf("zone/podq saved %s, err (%s)", k, rs.Bytex().String()))
	}

	return inapi.NewPbOpLogEntry("", inapi.PbOpLogOK, "sync to host/"+oprep.Node)
}
