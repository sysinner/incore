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

package podrunner

import (
	"fmt"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	pod_pull = false
	pod_push = false
	pod_mu   sync.Mutex

	pod_instances    = map[string]*inapi.Pod{}
	pod_status_queue = make(chan string, 500)

	pod_statuses_inited = false
	pod_statuses        = map[string]*inapi.PodStatusReplica{}

	max_pod_limit             = 100
	status_synctime_max int64 = 120 // time of seconds

)

func pod_ops_pulling() {

	//
	if in_sts.ZoneId == "" {
		return
	}

	//
	pod_mu.Lock()
	if pod_pull {
		pod_mu.Unlock()
		return
	}
	pod_pull = true
	pod_mu.Unlock()

	//
	defer func() {
		pod_mu.Lock()
		pod_pull = false
		pod_mu.Unlock()
	}()

	// TOPO Watch()
	rs := in_db.HiMaster.PvScan(
		inapi.NsZoneHostBoundPod(
			in_sts.ZoneId,
			in_sts.Host.Meta.Id,
			"",
			0,
		), "", "", max_pod_limit)
	if !rs.OK() {
		return
	}

	rss := rs.KvList()
	for _, v := range rss {

		var pod inapi.Pod

		if err := v.Decode(&pod); err != nil {
			continue
		}

		if pod.Meta.ID == "" ||
			pod.Operate.Replica == nil ||
			pod.Operate.Replica.Node != in_sts.Host.Meta.Id {
			continue
		}

		// hlog.Printf("info", "pull pod %s", pod.Meta.ID)

		data_ctr_update(pod)
	}

	// TOPO
	if !pod_statuses_inited {

		rs = in_db.HiMaster.PvScan(
			inapi.NsZoneHostBoundPodReplicaStatus(
				in_sts.ZoneId,
				in_sts.Host.Meta.Id,
				"",
				0,
			), "", "", 10000)
		if !rs.OK() {
			return
		}

		rss := rs.KvList()
		for _, v := range rss {

			var obj inapi.PodStatusReplica
			if err := v.Decode(&obj); err != nil {
				continue
			}

			pod_statuses[string(v.Key)] = &obj
		}

		pod_statuses_inited = true
	}
}

func data_ctr_update(pod inapi.Pod) {

	pod_mu.Lock()
	defer pod_mu.Unlock()

	repkey := inapi.NsZonePodOpRepKey(pod.Meta.ID, pod.Operate.Replica.Id)
	prev, ok := pod_instances[repkey]

	init_home := false

	if ok {

		if prev.Meta.Updated < 1 || prev.Meta.Updated != pod.Meta.Updated {

			prev.Meta.Updated = pod.Meta.Updated
			prev.Spec = pod.Spec
			prev.Operate.Action = pod.Operate.Action
			prev.Operate.Replica = pod.Operate.Replica

			// TODO destroy bound apps
			if pod.Apps != nil {

				if prev.Apps == nil {
					prev.Apps = pod.Apps
				} else {

					for _, a := range pod.Apps {
						prev.Apps.Sync(a)
					}
				}
			}

			init_home = true
		}

	} else {

		if len(pod_instances) > max_pod_limit {
			return
		}

		prev = &pod

		pod_instances[repkey] = prev
		init_home = true
	}

	if init_home {

		sysdir := vol_agentsys_dir(pod.Meta.ID, pod.Operate.Replica.Id)
		if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
			return
		}
		if err := json.EncodeToFile(prev, sysdir+"/pod_instance.json", "  "); err != nil {
			return
		}
	}

	box_keeper.ctr_sync(prev)
}

func pod_status_sync(v string) {

	if len(pod_status_queue) > 100 {
		return
	}

	pod_status_queue <- v
}

func pod_status_pushing() {

	//
	if in_sts.ZoneId == "" {
		return
	}

	//
	pod_mu.Lock()
	if pod_push {
		pod_mu.Unlock()
		return
	}
	pod_push = true
	pod_mu.Unlock()

	//
	defer func() {
		pod_mu.Lock()
		pod_push = false
		pod_mu.Unlock()
	}()

	for repkey := range pod_status_queue {

		pod, ok := pod_instances[repkey]
		if !ok {
			continue
		}

		status, ok := pod_statuses[repkey]
		if !ok {
			status = &inapi.PodStatusReplica{}
		}

		sync, found := false, false

		for _, bspec := range pod.Spec.Boxes {

			box_inst_name := fmt.Sprintf("%s-%s-%s",
				pod.Meta.ID,
				inutils.Uint16ToHexString(pod.Operate.Replica.Id),
				bspec.Name,
			)

			inst, ok := box_keeper.instances[box_inst_name]
			if !ok {
				continue
			}

			for i, bv := range status.Boxes {

				if bv.Name != bspec.Name {
					continue
				}

				found = true

				if status.Boxes[i].Sync(inst.Status) {
					sync = true
				}

				break
			}

			if !found {
				status.Boxes = append(status.Boxes, inst.Status)
				sync, found = true, false
			}
		}

		//
		if len(status.Boxes) > len(pod.Spec.Boxes) {

			bsn := []inapi.PodBoxStatus{}

			for _, bs := range status.Boxes {

				for _, b := range pod.Spec.Boxes {

					if b.Name == bs.Name {
						bsn = append(bsn, bs)
						break
					}
				}
			}

			sync = true

			status.Boxes = bsn
		}

		//
		statusPhase := status.Phase

		if len(pod.Spec.Boxes) != len(status.Boxes) {

			statusPhase = inapi.OpStatusPending

		} else {

			s_diff := map[inapi.OpType]int{}

			for _, v := range status.Boxes {

				switch v.Phase {

				case inapi.OpStatusRunning,
					inapi.OpStatusStopped,
					inapi.OpStatusFailed,
					inapi.OpStatusDestroyed:
					s_diff[v.Phase]++

				default:
					s_diff[inapi.OpStatusPending]++
				}
			}

			if len(s_diff) == 1 {

				for k := range s_diff {
					statusPhase = k
					break
				}

			} else if _, ok := s_diff[inapi.OpStatusFailed]; ok {
				statusPhase = inapi.OpStatusFailed
			} else {
				statusPhase = inapi.OpStatusPending
			}
		}

		if status.Phase != statusPhase {
			status.Phase = statusPhase
			sync = true
		}

		//
		if sync || (time.Now().UTC().Unix()-status.Updated.Time().Unix()) > status_synctime_max {

			path := inapi.NsZoneHostBoundPodReplicaStatus(
				in_sts.ZoneId,
				in_sts.Host.Meta.Id,
				pod.Meta.ID,
				pod.Operate.Replica.Id,
			)

			status.Updated = types.MetaTimeNow()

			if rs := in_db.HiMaster.PvPut(path, *status, nil); !rs.OK() {
				hlog.Printf("error", "hostlet/pod StatusSync %s SET Failed %s",
					pod.Meta.ID, rs.Bytex().String())
			}
		}
	}

}
