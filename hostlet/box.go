// Copyright 2018 Eryx <evorui аt gmаil dοt cοm>, All rights reserved.
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

package hostlet

import (
	"time"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
)

func boxActionRefreshEntry(
	instName string,
	pod *inapi.PodRep,
	box_spec inapi.PodSpecBoxBound,
) *napi.BoxInstance {

	if len(box_spec.Command) < 1 {
		box_spec.Command = []string{"/home/action/.sysinner/ininit"}
	}

	inst := nstatus.BoxActives.Get(instName)
	if inst == nil {

		inst = &napi.BoxInstance{
			ID:           "",
			PodID:        pod.Meta.ID,
			Name:         instName,
			PodOpVersion: pod.Operate.Version,
			Spec:         box_spec,
			Apps:         pod.Apps,
			Replica:      pod.Replica,
			Stats:        inapi.NewPbStatsSampleFeed(napi.BoxStatsSampleCycle),
			UpUpdated:    uint32(time.Now().Unix()),
		}

		nstatus.BoxActives.Set(inst)

		ConfigFlush()

	} else {

		if pod.Operate.Version > inst.PodOpVersion {
			inst.PodOpVersion = pod.Operate.Version
		}

		if inst.Spec.Updated < 1 || inst.Spec.Updated != box_spec.Updated {
			inst.Spec = box_spec
		}

		if pod.Replica.Updated > inst.Replica.Updated {
			inst.Replica = pod.Replica
		}

		nstatus.BoxActives.SpecCpuSetsDesired(inst)
	}

	// TODO destroy bound apps
	if pod.Apps != nil {

		if inst.Apps == nil {
			inst.Apps = pod.Apps
		} else {

			for _, a := range pod.Apps {
				inst.Apps.Sync(a)
			}
		}
	}

	if !inst.Replica.Ports.Equal(pod.Replica.Ports) {
		inst.Replica.Ports = pod.Replica.Ports
	}

	inst.VolumeMountsRefresh()

	return inst
}

func boxStatusSync(item *napi.BoxInstance) {

	if inst := nstatus.BoxActives.Get(item.Name); inst != nil {

		if len(inst.Status.ImageOptions) != len(item.Status.ImageOptions) {
			inst.Status.ImageOptions = item.Status.ImageOptions
		}

		if len(inst.Status.Mounts) != len(item.Status.Mounts) {
			inst.Status.Mounts = item.Status.Mounts
		}

		if len(inst.Status.Ports) != len(item.Status.Ports) {
			inst.Status.Ports = item.Status.Ports
		}

		if len(inst.Status.Executors) != len(item.Status.Executors) {
			inst.Status.Executors = item.Status.Executors
		}

		if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionMigrated) {
			item.Status.Action = item.Status.Action | inapi.OpActionMigrated
		}

		if !napi.ArrayInt32Equal(inst.Status.CpuSets, item.Status.CpuSets) {
			inst.Status.CpuSets = item.Status.CpuSets
		}

		inst.Status.Sync(&item.Status)

		if inst.Replica.Action != item.Replica.Action && item.Replica.Action > 0 {
			inst.Replica.Action = item.Replica.Action
		}

		if inapi.OpActionAllow(item.Status.Action, inapi.OpActionDestroyed) {
			inst.ID, item.ID = "", ""
		} else if item.ID != "" {
			inst.ID = item.ID
		}

		hlog.Printf("debug", "boxStatusSync %s, action %d", item.Name, item.Status.Action)

	} else {
		nstatus.BoxActives.StatusSet(item)
		ConfigFlush()
	}
}

func boxStatsSync(v *napi.BoxInstanceStatsFeed) {

	if inst := nstatus.BoxActives.Get(v.Name); inst != nil {
		if inst.Stats == nil {
			inst.Stats = inapi.NewPbStatsSampleFeed(napi.BoxStatsSampleCycle)
		}
		for _, v2 := range v.Items {
			inst.Stats.SampleSync(v2.Name, v.Time, v2.Value, false)
		}
	}
}
