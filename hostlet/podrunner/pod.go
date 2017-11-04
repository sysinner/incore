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
	"errors"
	"fmt"
	"os"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"

	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	max_pod_limit = 200
)

func pod_op_pull() {

	//
	if in_sts.ZoneId == "" {
		return
	}

	// TOPO Watch()
	rss := in_db.HiMaster.PvScan(
		inapi.NsZoneHostBoundPod(
			in_sts.ZoneId,
			in_sts.Host.Meta.Id,
			"",
			0,
		), "", "", max_pod_limit,
	).KvList()

	for _, v := range rss {

		var pod inapi.Pod
		if err := v.Decode(&pod); err != nil {
			fmt.Println(err)
			continue
		}

		if pod.Meta.ID == "" ||
			pod.Operate.Replica == nil ||
			pod.Operate.Replica.Node != in_sts.Host.Meta.Id {
			continue
		}

		if err := pod_op_pull_entry(&pod); err != nil {
			PodRepOpLogs.LogSet(
				pod.OpRepKey(), pod.Operate.Version,
				oplog_podpull, inapi.PbOpLogError, fmt.Sprintf("pod/%s err:%s", pod.Meta.ID, err.Error()),
			)
		} else {
			PodRepOpLogs.LogSet(
				pod.OpRepKey(), pod.Operate.Version,
				oplog_podpull, inapi.PbOpLogOK, fmt.Sprintf("pod/%s ok", pod.Meta.ID),
			)
		}
	}
}

func pod_op_pull_entry(pod *inapi.Pod) error {

	// fmt.Println("hostlet", pod.Meta.ID, inapi.OpActionStrings(pod.Operate.Action), pod.Operate.Version)

	prev := PodRepActives.Get(pod.IterKey())

	if prev != nil {
		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) &&
			inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			return nil
		}
	}

	sysdir := vol_agentsys_dir(pod.Meta.ID, pod.Operate.Replica.Id)

	if prev == nil {

		if len(PodRepActives) > max_pod_limit {
			return errors.New("no available host resources in this moment")
		}

		if _, err := os.Stat(sysdir); os.IsNotExist(err) {
			if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
				hlog.Printf("error", "hostlet/pod-pull %s %s", pod.Meta.ID, err.Error())
				return err
			}
		}

		prev = pod

		PodRepActives.Set(prev)

	} else if pod.Operate.Version > prev.Operate.Version ||
		(pod.Meta.Updated > 1 && pod.Meta.Updated != prev.Meta.Updated) {

		prev.Meta.Updated = pod.Meta.Updated
		prev.Spec = pod.Spec

		prev.Operate = pod.Operate
		// hlog.Printf("error", "hostlet/pod-pull %s action %d", pod.Operate.Action)

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
		return nil
	}

	if _, err := os.Stat(sysdir); os.IsNotExist(err) {
		if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
			hlog.Printf("error", "hostlet/pod-pull %s %s", prev.Meta.ID, err.Error())
			return err
		}
	}
	if err := json.EncodeToFile(prev, sysdir+"/pod_instance.json", "  "); err != nil {
		hlog.Printf("error", "hostlet/pod-pull %s %s", prev.Meta.ID, err.Error())
		return err
	}

	return nil
}
