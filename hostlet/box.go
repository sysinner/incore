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
	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
)

func boxActionRefresh() []*napi.BoxInstance {

	actions := []*napi.BoxInstance{}
	dels := []string{}

	nstatus.PodRepActives.Each(func(pod *inapi.Pod) {

		for _, box := range pod.Spec.Boxes {

			inst_name := napi.BoxInstanceName(pod.Meta.ID, pod.Operate.Replica, box.Name)

			if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
				nstatus.BoxActives.Del(inst_name)
				continue
			}

			inst := boxActionRefreshEntry(inst_name, pod, box)
			actions = append(actions, inst)
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			dels = append(dels, pod.Meta.ID)
		}
	})

	for _, v := range dels {
		nstatus.PodRepActives.Del(v)
	}

	return actions
}

func boxActionRefreshEntry(
	inst_name string,
	pod *inapi.Pod,
	box_spec inapi.PodSpecBoxBound,
) *napi.BoxInstance {

	if len(box_spec.Command) < 1 {
		box_spec.Command = []string{"/home/action/.sysinner/ininit"}
	}

	inst := nstatus.BoxActives.Get(inst_name)
	if inst == nil {

		inst = &napi.BoxInstance{
			ID:           "",
			Name:         inst_name,
			PodOpAction:  pod.Operate.Action,
			PodOpVersion: pod.Operate.Version,
			PodID:        pod.Meta.ID,
			RepId:        pod.Operate.Replica.Id,
			Spec:         box_spec,
			Apps:         pod.Apps,
			Ports:        pod.Operate.Replica.Ports, // TODO
			Stats:        inapi.NewPbStatsSampleFeed(napi.BoxStatsSampleCycle),
		}

		nstatus.BoxActives.Set(inst)

	} else {

		if pod.Operate.Action != inst.PodOpAction && pod.Operate.Action > 0 {
			inst.PodOpAction = pod.Operate.Action
		}

		if pod.Operate.Version > inst.PodOpVersion {
			inst.PodOpVersion = pod.Operate.Version
		}

		if inst.Spec.Updated < 1 || inst.Spec.Updated != box_spec.Updated {
			inst.Spec = box_spec
		}
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

	if !inst.Ports.Equal(pod.Operate.Replica.Ports) {
		inst.Ports = pod.Operate.Replica.Ports
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

		inst.Status.Sync(&item.Status)

		if inst.PodOpAction != item.PodOpAction && item.PodOpAction > 0 {
			inst.PodOpAction = item.PodOpAction
		}

		if inapi.OpActionAllow(item.Status.Action, inapi.OpActionDestroyed) {
			inst.ID, item.ID = "", ""
		} else if item.ID != "" {
			inst.ID = item.ID
		}

		hlog.Printf("debug", "boxStatusSync %s, action %d", item.Name, item.Status.Action)

	} else {
		// nstatus.BoxActives.Set(item)
	}
}

func boxStatsSync(v *napi.BoxInstanceStatsFeed) {

	if inst := nstatus.BoxActives.Get(v.Name); inst != nil && inst.Stats != nil {
		for _, v2 := range v.Items {
			inst.Stats.SampleSync(v2.Name, v.Time, v2.Value)
		}
	}
}
