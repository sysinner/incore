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
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	Scheduler inapi.Scheduler
	pod_ops   = map[string]*inapi.PodOperate{}
)

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
	for _, cell := range status.Zone.Cells {
		scheduler_exec_cell(cell.Meta.Id)
	}

	return nil
}

func scheduler_exec_cell(cell_id string) {

	podqs := []inapi.Pod{}

	// TODO pager
	if rs := data.ZoneMaster.PvScan(
		inapi.NsZonePodOpQueue(status.ZoneId, cell_id, ""), "", "", 1000); rs.OK() {

		rss := rs.KvList()
		for _, v := range rss {

			var pod inapi.Pod
			if err := v.Decode(&pod); err == nil {

				if pod.Spec != nil &&
					pod.Spec.Cell != "" {
					podqs = append(podqs, pod)
				} else {
					// TODO error log
				}
			}
		}
	}

	if len(podqs) == 0 {
		return
	}

	hlog.Printf("info", "scheduling %d podqs", len(podqs))

	for _, podq := range podqs {

		var (
			prev      inapi.Pod
			host      *inapi.ResHost
			host_sync = false
		)

		if rs := data.ZoneMaster.PvGet(
			inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID),
		); rs.OK() {

			if err := rs.Decode(&prev); err != nil {
				hlog.Printf("error", "bad prev podq #%s instance", podq.Meta.ID)
				// TODO error log
				continue
			}

		} else if !rs.NotFound() {
			// may be io connection error
			hlog.Printf("error", "failed on get podq #%s", podq.Meta.ID)
			continue
		}

		if len(prev.Operate.Replicas) > 0 {
			podq.Operate.Replicas = prev.Operate.Replicas
		} else {
			podq.Operate.Replicas.CapacitySet(podq.Operate.ReplicaCap)
		}

		// podq.OperateRefresh()

		for _, oprep := range podq.Operate.Replicas {

			if oprep.Node == "" {

				host_id, err := Scheduler.Schedule(podq, status.ZoneHostList)

				if err != nil || host_id == "" {
					// TODO error log
					continue
				}

				host = status.ZoneHostList.Item(host_id)
				if host == nil {
					continue
				}

				podq.Operate.Replicas.Set(inapi.PodOperateReplica{
					Id:   oprep.Id,
					Node: host_id,
				})

				res := podq.Spec.ResComputeBound()
				host.SyncOpCpu(res.CpuLimit)
				host.SyncOpRam(res.MemLimit)

				host_sync = true

				hlog.Printf("info", "schedule podq #%s on to host #%s (new)", podq.Meta.ID, host_id)
			} else {

				host = status.ZoneHostList.Item(oprep.Node)
				if host == nil {
					// TODO re-schedule
					continue
				}

				var (
					res   = podq.Spec.ResComputeBound()
					res_p = prev.Spec.ResComputeBound()
				)

				if res.CpuLimit != res_p.CpuLimit ||
					res.MemLimit != res_p.MemLimit {

					host.SyncOpCpu(res.CpuLimit - res_p.CpuLimit)
					host.SyncOpRam(res.MemLimit - res_p.MemLimit)

					host_sync = true
				}
			}

			if host == nil {
				hlog.Printf("warn", "no available host schedule")
				continue
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

				for _, popv := range ports {
					nsz.Sync(popv.BoxPort, oprep.Id, host_peer_lan.IP(), popv.HostPort)
				}

				if nsz.SyncChanged() {
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
					continue
				}
			}
		}

		if prev.Payment != nil {
			podq.Payment = prev.Payment
		}

		if podq.Payment == nil {
			podq.Payment = &inapi.PodPayment{
				TimeStart: uint32(time.Now().Unix()),
				TimeClose: 0,
				Prepay:    0,
				Payout:    0,
			}
		}

		if rs := data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, podq.Meta.ID), podq, nil); !rs.OK() {
			hlog.Printf("error", "zone/podq saved %s, err (%s)", podq.Meta.ID, rs.Bytex().String())
			continue
		}

		err_no := 0
		changed := false

		for _, oprep := range podq.Operate.Replicas {

			podq.Operate.Replica = oprep
			k := inapi.NsZoneHostBoundPod(status.ZoneId, oprep.Node, podq.Meta.ID, oprep.Id)

			if rs := data.ZoneMaster.PvPut(k, podq, nil); !rs.OK() {
				hlog.Printf("error", "zone/podq saved %s, err (%s)", k, rs.Bytex().String())
				err_no++
				break
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
				"zone-master/scheduler",
				inapi.PbOpLogOK, "sync to host/"+oprep.Node,
			)

			changed = false
			status.ZonePodRepStatusSets, changed = inapi.PbPodRepStatusSliceSync(
				status.ZonePodRepStatusSets, prs,
			)
			if changed {
				if rs := data.ZoneMaster.PvPut(prs_path, prs, nil); !rs.OK() {
					hlog.Printf("error", "zone/pod-rep-status saved %s, err (%s)", podq.OpRepKey(), rs.Bytex().String())
					err_no++
					break
				}
			}
		}

		if err_no == 0 {
			data.ZoneMaster.PvDel(inapi.NsZonePodOpQueue(status.ZoneId, podq.Spec.Cell, podq.Meta.ID), nil)
		}
	}
}
