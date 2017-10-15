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
	"os"
	"sync"

	"github.com/lessos/lessgo/encoding/json"

	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	pod_pull      = false
	pod_mu        sync.Mutex
	max_pod_limit = 100
)

func pod_op_pull() {

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

		// data_ctr_update(pod)
		pod_op_pull_entry(&pod)
	}
}

func pod_op_pull_entry(pod *inapi.Pod) {

	prev := PodActives.Get(pod.IterKey())
	if prev == nil {

		if len(PodActives) > max_pod_limit {
			return
		}

		sysdir := vol_agentsys_dir(pod.Meta.ID, pod.Operate.Replica.Id)
		if _, err := os.Stat(sysdir); os.IsNotExist(err) {
			if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
				return
			}
		}

		prev = pod

		PodActives.Set(prev)

	} else if pod.Meta.Updated > 1 && pod.Meta.Updated != prev.Meta.Updated {

		prev.Meta.Updated = pod.Meta.Updated
		prev.Spec = pod.Spec

		prev.Operate = pod.Operate

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

	} else {
		return
	}

	sysdir := vol_agentsys_dir(prev.Meta.ID, prev.Operate.Replica.Id)
	if _, err := os.Stat(sysdir); os.IsNotExist(err) {
		if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
			return
		}
	}
	if err := json.EncodeToFile(prev, sysdir+"/pod_instance.json", "  "); err != nil {
		return
	}
}
