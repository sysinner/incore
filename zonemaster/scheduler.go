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
	"errors"

	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/logger"
	"github.com/lessos/lessgo/types"

	// "github.com/lessos/lessgo/encoding/json"

	"code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/status"
)

var (
	Scheduler losapi.Scheduler
	pod_ops   = map[string]*losapi.PodOperate{}
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

	pods := []losapi.Pod{}

	// TODO pager
	if rs := data.ZoneMaster.PvScan(
		losapi.NsZonePodSetQueue(status.ZoneId, cell_id, ""), "", "", 1000); rs.OK() {

		rss := rs.KvList()
		for _, v := range rss {

			var pod losapi.Pod
			if err := v.Decode(&pod); err == nil {

				if pod.Spec != nil &&
					pod.Spec.Cell != "" {
					pods = append(pods, pod)
				} else {
					// TODO error log
				}
			}
		}
	}

	if len(pods) == 0 {
		return
	}

	logger.Printf("info", "scheduling %d pods", len(pods))

	for _, pod := range pods {

		var (
			prev      losapi.Pod
			host      *losapi.ResHost
			host_sync = false
		)

		if rs := data.ZoneMaster.PvGet(
			losapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
		); rs.OK() {

			if err := rs.Decode(&prev); err != nil {
				logger.Printf("error", "bad prev pod #%s instance", pod.Meta.ID)
				// TODO error log
				continue
			}

		} else if !rs.NotFound() {
			// may be io connection error
			logger.Printf("error", "failed on get pod #%s", pod.Meta.ID)
			continue
		}

		if prev.Operate.Node != "" {
			pod.Operate.Node = prev.Operate.Node
		}

		if pod.Operate.Node == "" {

			host_id, err := Scheduler.Schedule(pod, status.ZoneHostList)

			if err != nil || host_id == "" {
				// TODO error log
				continue
			}

			host = status.ZoneHostList.Item(host_id)
			if host == nil {
				continue
			}

			pod.Operate.Node = host_id

			res := pod.Spec.ResComputeBound()
			host.SyncOpCpu(res.CpuLimit)
			host.SyncOpRam(res.MemLimit)

			host_sync = true

			logger.Printf("info", "schedule pod #%s on to host #%s (new)", pod.Meta.ID, host_id)
		} else {

			host = status.ZoneHostList.Item(pod.Operate.Node)
			if host == nil {
				// TODO re-schedule
				continue
			}

			var (
				res   = pod.Spec.ResComputeBound()
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
			logger.Printf("warn", "no available host schedule")
			continue
		}

		pod.OperateRefresh()

		host_peer_lan := losapi.HostNodeAddress(host.Spec.PeerLanAddr)
		host_peer_port := host_peer_lan.Port()

		for i, pv := range pod.Operate.Ports {

			if pv.HostPort > 0 {

				if pv.HostPort == host_peer_port {

					pod.Operate.Ports[i].HostPort = 0

					logger.Printf("warn", "the host port %s:%d already in use ",
						host.Spec.PeerLanAddr, pv.HostPort)

				} else if host.OpPortHas(pv.HostPort) {

					if ppv := prev.Operate.Ports.Get(pv.BoxPort); ppv == nil ||
						ppv.HostPort != pv.HostPort {

						pod.Operate.Ports[i].HostPort = 0

						logger.Printf("warn", "the host port %s:%d is already allocated",
							host.Spec.PeerLanAddr, pv.HostPort)
					}
				} else {
					host.OpPortAlloc(pv.HostPort)
					host_sync = true
				}

				continue
			}

			for _, pvp := range prev.Operate.Ports {

				if pvp.BoxPort != pv.BoxPort {
					continue
				}

				if pvp.HostPort > 0 {
					pod.Operate.Ports.Sync(*pvp)
				}

				break
			}
		}

		// TODO delete unused port

		//
		ports_alloc := []uint16{}
		for i, p := range pod.Operate.Ports {

			if p.HostPort > 0 {
				continue
			}

			if port_alloc := host.OpPortAlloc(0); port_alloc > 0 {

				pod.Operate.Ports[i].HostPort = port_alloc
				host_sync = true
				ports_alloc = append(ports_alloc, port_alloc)

				logger.Printf("info", "new port alloc to %s:%d",
					host.Spec.PeerLanAddr, port_alloc)

			} else {
				logger.Printf("warn", "host #%s res-port out range", host.Meta.Id)
			}
		}

		//
		if len(pod.Operate.Ports) > 0 {

			var nsz losapi.NsPodServiceMap

			if rs := data.ZoneMaster.PvGet(losapi.NsZonePodServiceMap(pod.Meta.ID)); rs.OK() {
				rs.Decode(&nsz)
			}

			if nsz.User == "" {
				nsz.User = pod.Meta.User
			}

			for _, popv := range pod.Operate.Ports {
				nsz.Sync(popv.BoxPort, 0, host_peer_lan.IP(), popv.HostPort)
			}

			if nsz.SyncChanged() {
				nsz.Updated = uint64(types.MetaTimeNow())
				data.ZoneMaster.PvPut(losapi.NsZonePodServiceMap(pod.Meta.ID), nsz, &skv.PathWriteOptions{
					Force: true,
				})
			}
		}

		if host_sync {

			logger.Printf("info", "host #%s sync changes", host.Meta.Id)

			host.OpPortSort()

			if rs := data.ZoneMaster.PvPut(
				losapi.NsZoneSysHost(status.ZoneId, host.Meta.Id), host, &skv.PathWriteOptions{
					Force: true,
				},
			); !rs.OK() {
				logger.Printf("error", "host #%s sync changes failed %s", host.Meta.Id, rs.Bytex().String())
				for _, pa := range ports_alloc {
					host.OpPortFree(pa)
				}
				continue
			}
		}

		for _, k := range []string{
			losapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID),
			losapi.NsZoneHostBoundPod(status.ZoneId, pod.Operate.Node, pod.Meta.ID),
		} {

			if rs := data.ZoneMaster.PvPut(k, pod, &skv.PathWriteOptions{
				Force: true,
			}); !rs.OK() {
				logger.Printf("error", "zone/pod saved %s, err (%s)", k, rs.Bytex().String())
				continue
			}
		}

		logger.Printf("info", "zone/pod #%s sync/queue updated", pod.Meta.ID)
		/*
			if js, err := json.Encode(pod, "  "); err == nil {
				fmt.Println("json", string(js))
			}
		*/

		data.ZoneMaster.PvDel(losapi.NsZonePodSetQueue(status.ZoneId, pod.Spec.Cell, pod.Meta.ID), &skv.PathWriteOptions{
			Force: true,
		})
	}
}
