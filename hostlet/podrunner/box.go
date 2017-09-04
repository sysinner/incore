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

package podrunner

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sync"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/losutils"
)

type BoxKeeper struct {
	mu        sync.Mutex
	instances map[string]*BoxInstance
	inited    bool
	sets      types.ArrayString
	actions   chan string
	hidocker  *docker.Client
	mmu       *locker.HashPool
}

var (
	box_keeper      BoxKeeper
	err             error
	docker_unixsock = "unix:///var/run/docker.sock"
	box_name_pat    = regexp.MustCompile("^([0-9a-f]{12,20})-([0-9a-f]{4})-([a-z]{1}[a-z0-9]{0,19})$")
	cmd_install     = "/usr/bin/install"
)

func init() {

	if path, err := exec.LookPath("install"); err == nil {
		cmd_install = path
	}

	box_keeper = BoxKeeper{
		instances: map[string]*BoxInstance{},
		inited:    false,
		actions:   make(chan string, 1000),
		hidocker:  nil,
		mmu:       locker.NewHashPool(runtime.NumCPU() * 2),
	}

	go box_keeper.status_watcher()
	go box_keeper.ctr_action()
}

func box_inst_name_parse(hostname string) (pod_id string, rep_id uint16, box_name string) {

	if ns := box_name_pat.FindStringSubmatch(hostname); len(ns) == 4 {

		rb, _ := hex.DecodeString(ns[2])
		rep_id = binary.BigEndian.Uint16(rb)

		return ns[1], rep_id, ns[3]
	}

	return "", 0, ""
}

func (br *BoxKeeper) ctr_sync(pod *losapi.Pod) {

	br.mu.Lock()
	defer br.mu.Unlock()

	//
	for _, box_spec := range pod.Spec.Boxes {

		inst_name := fmt.Sprintf(
			"%s-%s-%s",
			pod.Meta.ID, losutils.Uint16ToHexString(pod.Operate.Replica.Id), box_spec.Name,
		)

		if len(box_spec.Command) < 1 {
			box_spec.Command = []string{"/home/action/.los/lpinit"}
		}

		box, ok := box_keeper.instances[inst_name]
		if !ok {

			box = &BoxInstance{
				Name:        inst_name,
				PodOpAction: pod.Operate.Action,
				PodID:       pod.Meta.ID,
				RepId:       pod.Operate.Replica.Id,
				Spec:        box_spec,
				Apps:        pod.Apps,
				Ports:       pod.Operate.Replica.Ports, // TODO
			}

			box_keeper.instances[inst_name] = box

		} else {

			if pod.Operate.Action != box.PodOpAction {
				box.PodOpAction = pod.Operate.Action
			}

			if box.Spec.Updated < 1 || box.Spec.Updated != box_spec.Updated {
				box.Spec = box_spec
			}
		}

		/*
			// debug ...
			box.Spec.Ports.Sync(losapi.Port{
				Name:     "http",
				Protocol: losapi.ProtocolTCP,
				BoxPort:  8080,
			})
			box.Spec.Ports.Sync(losapi.Port{
				Name:     "ssh",
				Protocol: losapi.ProtocolTCP,
				BoxPort:  22,
			})
		*/

		// TODO destroy bound apps
		if pod.Apps != nil {

			if box.Apps == nil {
				box.Apps = pod.Apps
			} else {

				for _, a := range pod.Apps {
					box.Apps.Sync(a)
				}
			}
		}

		if !box.Ports.Equal(pod.Operate.Replica.Ports) {
			box.Ports = pod.Operate.Replica.Ports
		}

		box.volume_mounts_refresh()

		if len(br.actions) < 100 {
			br.actions <- inst_name
		}
	}

	// hlog.Printf("info", "nodelet/box CtrSync POD:%s", pod.Meta.ID)
}

func (br *BoxKeeper) status_update(item *BoxInstance) {

	br.mu.Lock()

	// hlog.Printf("info", "nodelet/box status_update POD:%s", item.PodID)

	if inst, ok := box_keeper.instances[item.Name]; ok {

		inst.Status.Sync(item.Status)

		if inst.PodOpAction != item.PodOpAction {
			inst.PodOpAction = item.PodOpAction
		}

		if item.Status.Phase == losapi.OpStatusDestroyed {
			inst.ID, item.ID = "", ""
		} else if item.ID != "" {
			inst.ID = item.ID
		}

	} else {
		box_keeper.instances[item.Name] = item
	}

	br.mu.Unlock()

	pod_status_sync(losapi.NsZonePodOpRepKey(item.PodID, item.RepId))
}

func (br *BoxKeeper) ctr_action() {

	for inst_name := range br.actions {

		go func(inst_name string) {

			br.mmu.Lock([]byte(inst_name))
			defer br.mmu.Unlock([]byte(inst_name))

			br.run(inst_name)

			// if err := br.run(inst_name); err != nil {
			// 	hlog.Printf("error", "nodelet/box ctr_action err:%s %s", inst_name, err.Error())
			// }
		}(inst_name)
	}
}
