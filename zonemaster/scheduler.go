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
	Scheduler         inapi.Scheduler
	zonePodSpecPlans  inapi.PodSpecPlans
	podResFreeTimeMin uint32 = 60
	podInQueue        types.ArrayString
	hostResUsages     = map[string]*hostUsageItem{}
	errServerError    = errors.New("server error")
)

const (
	oplogZms     = "zone-master/scheduler/alloc"
	oplogZmsFree = "zone-master/scheduler/destroy"
)

type destResReplica struct {
	Ports  inapi.ServicePorts `json:"ports,omitempty"`
	ResCpu int32              `json:"res_cpu,omitempty"` // Cores, (1 = .1 Cores)
	ResMem int32              `json:"res_mem,omitempty"` // MiB
	VolSys int32              `json:"vol_sys,omitempty"` // GiB
}

type hostUsageItem struct {
	cpu   int64 // 1000m
	mem   int64 // bytes
	ports types.ArrayUint32
}

func schedAction() error {

	if status.ZoneId == "" ||
		status.Zone == nil ||
		!status.ZoneHostListImported {
		return errors.New("Zone Status Not Ready")
	}

	if Scheduler == nil {
		return errors.New("No Scheduler Found")
	}

	if err := schedPodSpecPlanListRefresh(); err != nil {
		return err
	}

	hostResUsages = map[string]*hostUsageItem{}

	if err := schedPodListRefresh(); err != nil {
		return err
	}

	if err := schedHostListRefresh(); err != nil {
		return err
	}

	//
	podInQueue.Clean()

	//
	for _, cell := range status.Zone.Cells {
		schedPodListQueue(cell.Meta.Id)
	}

	schedPodListBound()

	return nil
}

func schedPodSpecPlanListRefresh() error {

	rs := data.GlobalMaster.PvScan(inapi.NsGlobalPodSpec("plan", ""), "", "", 1000)
	if !rs.OK() {
		return errors.New("gm/db error")
	}

	zonePodSpecPlans = inapi.PodSpecPlans{}
	rss := rs.KvList()
	for _, v := range rss {
		var specPlan inapi.PodSpecPlan
		if err := v.Decode(&specPlan); err == nil {
			specPlan.ChargeFix()
			zonePodSpecPlans = append(zonePodSpecPlans, &specPlan)
		}
	}

	if len(zonePodSpecPlans) > 0 {
		return nil
	}

	return errors.New("No PodSpecPlan Found")
}

func schedPodListRefresh() error {

	//
	var (
		tn = uint32(time.Now().Unix())
	)

	// local zone scheduled pods
	rs := data.ZoneMaster.PvScan(
		inapi.NsZonePodInstance(status.ZoneId, ""), "", "", 10000)
	if !rs.OK() {
		return errors.New("zm/db err")
	}

	rss := rs.KvList()
	for _, v := range rss {

		var pod inapi.Pod
		if err := v.Decode(&pod); err != nil {
			return err
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionHang) {

			//
			if uint32(time.Now().Unix())-pod.Operate.Operated > inapi.PodDestroyTTL {
				if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstanceDestroy(status.ZoneId, pod.Meta.ID), pod, nil); rs.OK() {
					rs = data.ZoneMaster.PvDel(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), nil)
					hlog.Printf("warn", "zone-master/pod/remove %s %v", pod.Meta.ID, rs.OK())
				}
			}
			continue
		}

		status.ZonePodList.Set(&pod)

		// TODO
		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStop|inapi.OpActionStopped) &&
			!inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionResFree) &&
			tn-pod.Operate.Operated > podResFreeTimeMin {

			pod.Operate.Action = pod.Operate.Action | inapi.OpActionResFree
			//
			if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod, nil); !rs.OK() {
				return errors.New("db error " + rs.Bytex().String())
			}
			hlog.Printf("warn", "zone-master/pod/stopped %s, SKIP ResMerge", pod.Meta.ID)
		}

		specRes := pod.Spec.ResComputeBound()
		for _, rp := range pod.Operate.Replicas {

			if rp.Node == "" {
				continue
			}

			if inapi.OpActionAllow(rp.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
				continue
			}

			hostRes, ok := hostResUsages[rp.Node]
			if !ok {
				hostRes = &hostUsageItem{}
				hostResUsages[rp.Node] = hostRes
			}

			if !inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionResFree) {
				hostRes.cpu += int64(specRes.CpuLimit) * 100
				hostRes.mem += int64(specRes.MemLimit) * inapi.ByteMB
			}

			for _, rpp := range rp.Ports {
				if rpp.HostPort > 0 {
					hostRes.ports.Set(uint32(rpp.HostPort))
				}
			}
		}
	}

	return nil
}

func schedHostListRefresh() error {

	//
	for _, host := range status.ZoneHostList.Items {

		var (
			res, ok = hostResUsages[host.Meta.Id]
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

	return nil
}

func schedPodListQueue(cellId string) {

	// TODO pager
	rss := data.GlobalMaster.PvScan(
		inapi.NsGlobalSetQueuePod(status.ZoneId, cellId, ""), "", "", 10000).KvList()
	if len(rss) == 0 {
		return
	}

	for _, v := range rss {

		var podq inapi.Pod

		if err := v.Decode(&podq); err != nil {
			hlog.Printf("error", "invalid data struct: %s", err.Error())
			continue
		}

		if podq.Spec == nil || podq.Spec.Cell != cellId {
			hlog.Printf("error", "invalid data struct: no spec/cell found")
			continue
		}

		err := schedPodItem(&podq, true)
		if err != nil {
			hlog.Print("error", "Scheduler Pod %s, ER %s", podq.Meta.ID, err.Error())
		}

		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			continue
		}

		if err == nil {
			data.GlobalMaster.PvDel(inapi.NsGlobalSetQueuePod(status.ZoneId, podq.Spec.Cell, podq.Meta.ID), nil)
			hlog.Printf("info", "zone/podq queue/clean %s", podq.Meta.ID)
			podInQueue.Set(podq.Meta.ID)
		}
	}
}

func schedPodListBound() {

	for _, podq := range status.ZonePodList {

		if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionHang) {
			continue
		}

		if podInQueue.Has(podq.Meta.ID) {
			continue
		}

		if podq.Spec == nil {
			hlog.Printf("error", "invalid data struct: no spec/cell found")
			continue
		}

		err := schedPodItem(podq, false)
		if err != nil {
			hlog.Print("error", "Scheduler Pod %s, ER %s", podq.Meta.ID, err.Error())
		}

		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			continue
		}
	}
}

func schedPodItem(podq *inapi.Pod, ctrl bool) error {

	// hlog.Printf("error", "exec podq #%s instance", podq.Meta.ID)

	if podq.Spec == nil {
		return errors.New("No PodSpec Found")
	}

	//
	specVol := podq.Spec.Volume("system")
	if specVol == nil {
		return errors.New("No Spec/Volume(system) Found")
	}

	var (
		tnStart = time.Now()
	)

	if rs := data.ZoneMaster.PvGet(
		inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID),
	); rs.OK() {

		var prev inapi.Pod
		if err := rs.Decode(&prev); err != nil {
			hlog.Printf("error", "bad prev podq #%s instance", podq.Meta.ID)
			// TODO error log
			return fmt.Errorf("bad prev podq #%s instance", podq.Meta.ID)
		}

		// TODO
		if len(prev.Operate.Replicas) > 0 {
			podq.Operate.Replicas = prev.Operate.Replicas
		}

		if podq.Operate.Version == prev.Operate.Version {
			for _, v := range prev.Operate.OpLog {
				podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog, v)
			}
		}

		if prev.Payment != nil {
			podq.Payment = prev.Payment
		}

		if !ctrl && inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionHang) {
			podq.Operate.Action = podq.Operate.Action | inapi.OpActionHang
		}

	} else if !rs.NotFound() {
		return errors.New("zm/db error")
	}

	if podq.OpResScheduleFit() {
		return nil
	}

	for _, v := range podq.Operate.Replicas {
		fmt.Println(podq.Meta.ID, v.RepId, inapi.OpActionStrings(podq.Operate.Action), inapi.OpActionStrings(v.Action), ctrl)
	}

	var (
		destRes   *destResReplica
		scaleup   = 0
		scaledown = 0
	)

	// PreChargeValid
	if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionStart) {

		if err := schedPodPreChargeValid(podq); err != nil {
			return err
		}

		specRes := podq.Spec.ResComputeBound()
		destRes = &destResReplica{
			ResCpu: specRes.CpuLimit,
			ResMem: specRes.MemLimit,
			VolSys: specVol.SizeLimit,
		}

	} else {

		destRes = &destResReplica{}
	}

	if len(podq.Operate.Replicas) > 0 {
		podq.Operate.Replicas.Sort()
	}

	for repid := uint32(0); repid < uint32(podq.Operate.ReplicaCap); repid++ {

		oplog := schedPodRep(podq, 0, repid, destRes)
		if oplog.Status == inapi.PbOpLogOK {
			scaleup += 1
		}
	}

	var (
		podStatus = status.ZonePodStatusList.Get(podq.Meta.ID)
		repOuts   = []*inapi.PodOperateReplica{}
	)

	// scaling down
	for _, rep := range podq.Operate.Replicas {

		if rep.RepId < uint32(podq.Operate.ReplicaCap) {
			continue
		}

		hlog.Printf("info", "%d", rep.RepId)

		scaledown += 1

		if podStatus != nil {
			hlog.Printf("info", "%d", rep.RepId)
			if repStatus := podStatus.RepGet(rep.RepId); repStatus != nil {
				hlog.Printf("info", "%d", rep.RepId)
				if inapi.OpActionAllow(rep.Action, inapi.OpActionDestroy) &&
					inapi.OpActionAllow(repStatus.Action, inapi.OpActionDestroyed) {
					hlog.Printf("info down ok", "%d", rep.RepId)
					scaledown -= 1
					repOuts = append(repOuts, rep)
				}
			}
		}

		if !inapi.OpActionAllow(rep.Action, inapi.OpActionDestroy) {
			hlog.Printf("info", "destroy %d", rep.RepId)
			rep.Action = inapi.OpActionDestroy
			schedPodRep(podq, inapi.OpActionDestroy, rep.RepId, &destResReplica{})
		}
	}

	for _, rep := range repOuts {

		hlog.Printf("warn", "zm/pod %s, scaling down rep %d, clean out operate/replica",
			podq.Meta.ID, rep.RepId)

		if rep.Node != "" {
			boundRepKey := inapi.NsZoneHostBoundPodRep(status.ZoneId, rep.Node, podq.Meta.ID, rep.RepId)

			if rs := data.ZoneMaster.PvDel(boundRepKey, nil); !rs.OK() {
				continue
			}
		}

		podq.Operate.Replicas.Del(rep.RepId)
	}

	var (
		opType = inapi.PbOpLogOK
		opMsg  = fmt.Sprintf("schedule %d/%d replicas in %v",
			scaleup, podq.Operate.ReplicaCap, time.Since(tnStart))
	)

	if scaleup != podq.Operate.ReplicaCap ||
		scaledown > 0 {
		opType = inapi.PbOpLogWarn
	}

	podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
		podq.Operate.OpLog,
		inapi.NewPbOpLogEntry(inapi.OpLogNsZoneMasterPodScheduleAlloc, opType, opMsg),
	)

	// TODO
	if false {
		if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionResFree) &&
			!inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionStop) {
			podq.Operate.Action = inapi.OpActionRemove(podq.Operate.Action, inapi.OpActionResFree)
		}
	}

	return nil
}

func schedPodRep(podq *inapi.Pod, opAction uint32,
	repId uint32, destRes *destResReplica) *inapi.PbOpLogEntry {

	var (
		host        *inapi.ResHost
		hostChanged = false
		opRep       = podq.Operate.Replicas.Get(repId)
		oplogKey    = inapi.OpLogNsZoneMasterPodScheduleRep(repId)
	)

	if opAction == 0 {
		opAction = podq.Operate.Action
	}

	//
	if opRep == nil {

		hostId, err := Scheduler.Schedule(*podq, status.ZoneHostList)

		if err != nil || hostId == "" {
			// TODO error log
			return inapi.NewPbOpLogEntry(oplogKey,
				inapi.PbOpLogWarn,
				"no available resources, waiting for allocation")
		}

		host = status.ZoneHostList.Item(hostId)
		if host == nil {
			return inapi.NewPbOpLogEntry(oplogKey,
				inapi.PbOpLogWarn,
				"no available resources, waiting for allocation")
		}

		opRep = &inapi.PodOperateReplica{
			RepId:  repId,
			Node:   hostId,
			Action: opAction,
			ResCpu: destRes.ResCpu,
			ResMem: destRes.ResMem,
			VolSys: destRes.VolSys,
		}

		podq.Operate.Replicas.Set(*opRep)
		podq.Operate.Replicas.Sort()

		host.SyncOpCpu(int64(destRes.ResCpu) * 100)
		host.SyncOpMem(int64(destRes.ResMem) * inapi.ByteMB)

		hostChanged = true

		// TOTK
		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn, "Data IO error")
		}

		hlog.Printf("info", "schedule pod #%s to host #%s (new)", podq.Meta.ID, hostId)

	} else {

		host = status.ZoneHostList.Item(opRep.Node)
		if host == nil {
			return inapi.NewPbOpLogEntry(oplogKey,
				inapi.PbOpLogWarn,
				fmt.Sprintf("host %s not found", opRep.Node))
		}
	}

	//
	if opRep.ResCpu != destRes.ResCpu ||
		opRep.ResMem != destRes.ResMem ||
		opRep.VolSys != destRes.VolSys {

		hlog.Printf("info", "rep %s-%d spec change", podq.Meta.ID, opRep.RepId)
		// inapi.ObjPrint(podq.Meta.ID, opRep)
		// inapi.ObjPrint(podq.Meta.ID, destRes)

		if inapi.OpActionAllow(opAction, inapi.OpActionStart) {

			//
			if err := Scheduler.ScheduleHostValid(host, inapi.ScheduleEntry{
				Cpu:    int64(destRes.ResCpu-opRep.ResCpu) * 100,
				Mem:    int64(destRes.ResMem-opRep.ResMem) * inapi.ByteMB,
				VolSys: int64(destRes.VolSys-opRep.VolSys) * inapi.ByteGB,
			}); err != nil {

				hlog.Printf("warn", "rep %s-%d, err %s",
					podq.Meta.ID, opRep.RepId, err.Error())
				//
				oplog := inapi.NewPbOpLogEntry(oplogKey,
					inapi.PbOpLogWarn,
					"no available resources (spec update), waiting for allocation")
				podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
					podq.Operate.OpLog,
					oplog)
				return oplog
			}
		}

		host.SyncOpCpu(int64(destRes.ResCpu-opRep.ResCpu) * 100)
		host.SyncOpMem(int64(destRes.ResMem-opRep.ResMem) * inapi.ByteMB)
		hostChanged = true

		opRep.ResCpu = destRes.ResCpu
		opRep.ResMem = destRes.ResMem
		opRep.VolSys = destRes.VolSys

		// inapi.ObjPrint(podq.Meta.ID, opRep)
	}

	if inapi.OpActionAllow(opAction, inapi.OpActionStart) {
		if ports, chg := schedPodRepNetPortAlloc(podq, opRep, host); chg {
			opRep.Ports = ports
			hostChanged = true
		}
	}

	if hostChanged {

		hlog.Printf("info", "host %s sync changes", host.Meta.Id)

		host.OpPortSort()

		if rs := data.ZoneMaster.PvPut(
			inapi.NsZoneSysHost(status.ZoneId, host.Meta.Id), host, nil,
		); !rs.OK() {
			hlog.Printf("error", "host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String())
			return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn,
				fmt.Sprintf("host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String()))
		}

		// TODO
	}

	// inapi.ObjPrint(podq.Meta.ID, podq)

	podq.Operate.Replica = opRep

	boundRepKey := inapi.NsZoneHostBoundPodRep(status.ZoneId, opRep.Node, podq.Meta.ID, opRep.RepId)

	if rs := data.ZoneMaster.PvPut(boundRepKey, podq, nil); !rs.OK() {
		hlog.Printf("error", "zone/podq saved %s, err (%s)", boundRepKey, rs.Bytex().String())
		return inapi.NewPbOpLogEntry("", inapi.PbOpLogWarn,
			fmt.Sprintf("zone/podq saved %s, err (%s)", boundRepKey, rs.Bytex().String()))
	}

	return inapi.NewPbOpLogEntry("", inapi.PbOpLogOK, "sync to host/"+opRep.Node)
}

func schedPodRepNetPortAlloc(
	podq *inapi.Pod,
	opRep *inapi.PodOperateReplica,
	host *inapi.ResHost,
) (inapi.ServicePorts, bool) {

	var (
		hostPeerLan  = inapi.HostNodeAddress(host.Spec.PeerLanAddr)
		hostPeerPort = hostPeerLan.Port()
		ports        = podq.AppServicePorts()
		hostChanged  = false
	)

	for i, pv := range ports {

		if pv.HostPort > 0 {

			if pv.HostPort == hostPeerPort {

				ports[i].HostPort = 0

				hlog.Printf("warn", "the host port %s:%d already in use ",
					host.Spec.PeerLanAddr, pv.HostPort)

			} else if host.OpPortHas(pv.HostPort) {

				if ppv := opRep.Ports.Get(pv.BoxPort); ppv == nil ||
					ppv.HostPort != pv.HostPort {

					ports[i].HostPort = 0

					hlog.Printf("warn", "the host port %s:%d is already allocated",
						host.Spec.PeerLanAddr, pv.HostPort)
				}
			} else {
				host.OpPortAlloc(pv.HostPort)
				hostChanged = true
			}

			continue
		}

		for _, pvp := range opRep.Ports {

			if pvp.BoxPort != pv.BoxPort {
				continue
			}

			if pvp.HostPort > 0 {
				ports.Sync(*pvp)
			}

			break
		}
	}

	// clean unused Ports
	for _, p := range opRep.Ports {
		if ports.Get(p.BoxPort) == nil {
			opRep.Ports.Del(p.BoxPort)
		}
	}

	// Assign new Host:Ports
	portsAlloc := []uint16{}
	for i, p := range ports {

		if p.HostPort > 0 {
			continue
		}

		if portAlloc := host.OpPortAlloc(0); portAlloc > 0 {

			ports[i].HostPort = portAlloc
			hostChanged = true

			portsAlloc = append(portsAlloc, portAlloc)

			hlog.Printf("info", "new port alloc to %s:%d",
				host.Spec.PeerLanAddr, portAlloc)

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
								Rep:  uint32(opRep.RepId),
								Ip:   hostPeerLan.IP(),
								Port: uint32(popv.HostPort),
							},
						},
					},
				},
			}) {
				changed = true
			}

			// } popv.BoxPort, opRep.RepId, hostPeerLan.IP(), popv.HostPort) {
			// 	changed = true
			// }
		}

		if changed {
			nsz.Updated = uint64(types.MetaTimeNow())
			data.ZoneMaster.PvPut(inapi.NsZonePodServiceMap(podq.Meta.ID), nsz, nil)
		}
	}

	return ports, hostChanged
}

func schedPodFree(podq *inapi.Pod) error {

	var (
		tnStart = time.Now()
		delNum  = 0
	)

	hlog.Printf("info", "destroy pod/%s, version %d, rep %d",
		podq.Meta.ID, podq.Operate.Version, len(podq.Operate.Replicas))

	for _, opRep := range podq.Operate.Replicas {

		if opRep.Node != "" {
			bdk := inapi.NsZoneHostBoundPodRep(status.ZoneId, opRep.Node, podq.Meta.ID, opRep.RepId)
			if rs := data.ZoneMaster.PvGet(bdk); rs.OK() {
				var podBound inapi.Pod
				if err := rs.Decode(&podBound); err == nil && podBound.Meta.ID == podq.Meta.ID {

					// hlog.Printf("info", "destroy pod/%s-%d action:%s",
					// 	podq.Meta.ID, opRep.RepId, strings.Join(inapi.OpActionStrings(podq.Operate.Action), ","))

					if !inapi.OpActionAllow(podBound.Operate.Action, inapi.OpActionDestroy) {

						podBound.Operate.Action = inapi.OpActionDestroy
						podBound.Operate.Version = podq.Operate.Version

						delNum += 1

						data.ZoneMaster.PvPut(bdk, podBound, nil)
						hlog.Printf("info", "destroy pod/%s-%d action:%s",
							podq.Meta.ID, opRep.RepId, strings.Join(inapi.OpActionStrings(podq.Operate.Action), ","))
					}
				}
			}
		} else {
			delNum += 1
		}
	}

	msg := fmt.Sprintf("scheduling %d replica sets in %v", len(podq.Operate.Replicas), time.Since(tnStart))

	podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(
		podq.Operate.OpLog,
		inapi.NewPbOpLogEntry(oplogZmsFree, inapi.PbOpLogInfo, msg),
	)

	if inapi.OpActionAllow(podq.Operate.Action, inapi.OpActionResFree) {
		podq.Operate.Action = inapi.OpActionRemove(podq.Operate.Action, inapi.OpActionResFree)
	}

	return nil
}

func schedPodPreChargeValid(podq *inapi.Pod) error {

	specPlan := zonePodSpecPlans.Get(podq.Spec.Ref.Id)
	if specPlan == nil {
		return fmt.Errorf("bad pod.Spec #%s", podq.Meta.ID)
	}

	chargeAmount := float64(0)

	// Volumes
	for _, v := range podq.Spec.Volumes {
		chargeAmount += iamapi.AccountFloat64Round(
			specPlan.ResVolumeCharge.CapSize*float64(v.SizeLimit), 4)
	}

	if podq.Spec.Box.Resources != nil {
		// CPU
		chargeAmount += iamapi.AccountFloat64Round(
			specPlan.ResComputeCharge.Cpu*(float64(podq.Spec.Box.Resources.CpuLimit)/10), 4)

		// RAM
		chargeAmount += iamapi.AccountFloat64Round(
			specPlan.ResComputeCharge.Mem*float64(podq.Spec.Box.Resources.MemLimit), 4)
	}

	chargeAmount = chargeAmount * float64(podq.Operate.ReplicaCap)

	chargeCycleMin := float64(3600)
	chargeAmount = iamapi.AccountFloat64Round(chargeAmount*(chargeCycleMin/3600), 2)
	if chargeAmount < 0.01 {
		chargeAmount = 0.01
	}

	tnu := uint32(time.Now().Unix())
	if rsp := iamclient.AccountChargePreValid(iamapi.AccountChargePrepay{
		User:      podq.Meta.User,
		Product:   types.NameIdentifier(fmt.Sprintf("pod/%s", podq.Meta.ID)),
		Prepay:    chargeAmount,
		TimeStart: tnu,
		TimeClose: tnu + uint32(chargeCycleMin),
	}, status.ZonePodChargeAccessKey()); rsp.Error != nil {

		status, msg := inapi.PbOpLogWarn, rsp.Error.Message
		if msg == "" {
			msg = "Error Code: " + rsp.Error.Code
		}
		if rsp.Error.Code == iamapi.ErrCodeAccChargeOut {
			status = inapi.PbOpLogError
		}
		podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
			inapi.NewPbOpLogEntry(inapi.OpLogNsZoneMasterPodScheduleCharge, status, msg),
		)
		return errors.New("")
	} else if rsp.Kind != "AccountCharge" {
		return errors.New("Network Error")
	}

	podq.Operate.OpLog, _ = inapi.PbOpLogEntrySliceSync(podq.Operate.OpLog,
		inapi.NewPbOpLogEntry(inapi.OpLogNsZoneMasterPodScheduleCharge, inapi.PbOpLogOK, "PreValid OK"),
	)

	return nil
}
