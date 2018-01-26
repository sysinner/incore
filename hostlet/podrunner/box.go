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
	"os/exec"
	"runtime"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/inapi"
	in_sts "github.com/sysinner/incore/status"
)

type BoxDriver interface {
	Name() string
	Run()
	ActionCommand(inst *BoxInstance) error
	StatsCollect(inst *BoxInstance, timo uint32) error
}

var (
	BoxDrivers []BoxDriver
)

type BoxKeeper struct {
	mu       sync.Mutex
	inited   bool
	sets     types.ArrayString
	actions  chan string
	hidocker *docker.Client
	mmu      *locker.HashPool
}

var (
	box_keeper      BoxKeeper
	err             error
	docker_unixsock = "unix:///var/run/docker.sock"
	cmd_install     = "/usr/bin/install"
)

func init() {

	if path, err := exec.LookPath("install"); err == nil {
		cmd_install = path
	}

	box_keeper = BoxKeeper{
		inited:   false,
		actions:  make(chan string, 1000),
		hidocker: nil,
		mmu:      locker.NewHashPool(runtime.NumCPU() * 2),
	}

	go box_keeper.docker_status_watcher()
	go box_keeper.stats_watcher()
	go box_keeper.ctr_action()
}

func (br *BoxKeeper) stats_watcher() {

	var (
		toffset = int64(time.Now().UnixNano()) % stats_tick
	)

	time.Sleep(time.Duration(stats_tick - toffset - 10e6))

	ticker := time.NewTicker(time.Duration(stats_tick))
	defer ticker.Stop()

	for {
		tl := <-ticker.C

		if !br.inited || in_sts.ZoneId == "" ||
			br.hidocker == nil || BoxActives.Size() > 100 {
			continue
		}

		timo := uint32(tl.UTC().Unix())

		BoxActives.Each(func(inst *BoxInstance) {

			if len(inst.ID) < 10 || !inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) {
				return
			}

			if inst.Stats == nil {
				inst.Stats = inapi.NewPbStatsSampleFeed(stats_sample_cycle)
			}

			go br.docker_stats_entry(inst, timo)
		})
	}
}

func (br *BoxKeeper) status_update(item *BoxInstance) {

	if inst := BoxActives.Get(item.Name); inst != nil {

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

	} else {
		BoxActives.Set(item)
	}
}

func (br *BoxKeeper) ctr_action() {

	for {

		time.Sleep(3e9)

		if !br.inited {
			continue
		}

		dels := []string{}

		PodRepActives.Each(func(pod *inapi.Pod) {
			// fmt.Println("ctr_action", pod.Meta.ID, inapi.OpActionStrings(pod.Operate.Action))

			for _, box := range pod.Spec.Boxes {

				inst_name := BoxInstanceName(pod.Meta.ID, pod.Operate.Replica, box.Name)

				if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
					BoxActives.Del(inst_name)
					continue
				}

				go br.ctr_action_box(inst_name, pod, box)
			}

			if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
				dels = append(dels, pod.Meta.ID)
			}
		})

		for _, v := range dels {
			PodRepActives.Del(v)
		}
	}
}

func (br *BoxKeeper) ctr_action_box(inst_name string, pod *inapi.Pod, box_spec inapi.PodSpecBoxBound) {

	if len(box_spec.Command) < 1 {
		box_spec.Command = []string{"/home/action/.sysinner/ininit"}
	}

	inst := BoxActives.Get(inst_name)
	if inst == nil {

		inst = &BoxInstance{
			ID:           "",
			Name:         inst_name,
			PodOpAction:  pod.Operate.Action,
			PodOpVersion: pod.Operate.Version,
			PodID:        pod.Meta.ID,
			RepId:        pod.Operate.Replica.Id,
			Spec:         box_spec,
			Apps:         pod.Apps,
			Ports:        pod.Operate.Replica.Ports, // TODO
			Stats:        inapi.NewPbStatsSampleFeed(stats_sample_cycle),
		}

		BoxActives.Set(inst)

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

	/*
		// debug ...
		box.Spec.Ports.Sync(inapi.Port{
			Name:     "http",
			Protocol: inapi.ProtocolTCP,
			BoxPort:  8080,
		})
		box.Spec.Ports.Sync(inapi.Port{
			Name:     "ssh",
			Protocol: inapi.ProtocolTCP,
			BoxPort:  22,
		})
	*/

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

	inst.volume_mounts_refresh()

	go func(inst *BoxInstance) {
		if err := br.docker_command(inst); err != nil {
			PodRepOpLogs.LogSet(
				pod.OpRepKey(), pod.Operate.Version,
				oplog_ctncmd, inapi.PbOpLogError, fmt.Sprintf("box/%s ERR:%s", inst.Name, err.Error()),
			)
		} else {
			PodRepOpLogs.LogSet(
				pod.OpRepKey(), pod.Operate.Version,
				oplog_ctncmd, inapi.PbOpLogOK, fmt.Sprintf("box/%s OK", inst.Name),
			)
		}
	}(inst)
}
