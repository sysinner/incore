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
	"os/exec"
	"strconv"
	"strings"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hooto/hlog4g/hlog"
	// "github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/net/portutil"

	in_cf "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	timeout = time.Second * 10
)

func (br *BoxKeeper) docker_status_watcher() {

	br.inited = false

	for {

		time.Sleep(2e9)

		if in_sts.Host.Meta.Id == "" {
			continue
		}

		if br.hidocker == nil {

			for {

				br.hidocker, err = docker.NewClient(docker_unixsock)
				if err != nil {
					hlog.Printf("fatal", "Can not connect to Docker Server, Error: %s", err)
					time.Sleep(1e9)
					continue
				}

				break
			}
		}

		// refresh current statuses
		rsc, err := br.hidocker.ListContainers(docker.ListContainersOptions{
			All: true,
		})
		if err != nil {
			hlog.Printf("error", "hidocker.ListContainers Error %v", err)
			br.inited = false
			continue
		}

		for _, vc := range rsc {
			br.docker_status_watch_entry(vc.ID)
		}

		if !br.inited {
			time.Sleep(2e9)
			br.inited = true
		}

		// // Diff and retry
		// for _, inst := range br.instances {

		// 	if inst.PodOpAction == 0 {
		// 		continue
		// 	}

		// 	if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) {

		// 		if inst.SpecDesired() {
		// 			continue
		// 		}
		// 	}

		// 	if inst.OpActionDesired() {
		// 		continue
		// 	}

		// 	if len(br.actions) < 100 {
		// 		inst.Retry++
		// 		br.actions <- inst.Name
		// 	}

		// 	hlog.Printf("error", "hostlet/box Retry %s:%d", inst.Name, inst.Retry)
		// }

		time.Sleep(2e9)
	}
}

func (br *BoxKeeper) docker_status_watch_entry(id string) {

	box_docker, err := br.hidocker.InspectContainer(id)
	if err != nil || box_docker == nil {
		return
	}

	pod_id, rep_id, box_name := BoxInstanceNameParse(box_docker.Config.Hostname)
	if pod_id == "" {
		return
	}

	tn := uint32(time.Now().Unix())

	inst := &BoxInstance{
		ID:    id,
		Name:  box_docker.Config.Hostname,
		PodID: pod_id,
		RepId: rep_id,
		Status: inapi.PbPodBoxStatus{
			Name:        box_name,
			Started:     uint32(box_docker.State.StartedAt.Unix()),
			Updated:     tn,
			ResCpuLimit: box_docker.HostConfig.CPUShares,
			ResMemLimit: box_docker.HostConfig.Memory,
			ImageDriver: inapi.PbPodSpecBoxImageDriver_Docker,
			ImageOptions: []*inapi.Label{
				{
					Name:  "docker/image/name",
					Value: box_docker.Config.Image,
				},
			},
			Command: box_docker.Config.Cmd,
		},
	}

	//
	for _, cm := range box_docker.Mounts {
		inst.Status.Mounts = append(inst.Status.Mounts, &inapi.PbVolumeMount{
			MountPath: cm.Destination,
			HostDir:   cm.Source,
			ReadOnly:  !cm.RW,
		})
	}

	// TODO
	if len(box_docker.HostConfig.PortBindings) > 0 {

		for box_dockerPortKey, box_dockerPorts := range box_docker.HostConfig.PortBindings {

			if len(box_dockerPorts) < 1 {
				continue
			}

			ps := strings.Split(string(box_dockerPortKey), "/")
			if len(ps) != 2 {
				continue
			}

			var (
				boxPort, _  = strconv.Atoi(ps[0])
				hostPort, _ = strconv.Atoi(box_dockerPorts[0].HostPort)
			)

			inst.Status.Ports = append(inst.Status.Ports, &inapi.PbServicePort{
				BoxPort:  uint32(boxPort),
				HostPort: uint32(hostPort),
				// Protocol: inapi.ProtocolTCP, //
				// HostIP:   conf.Config.HostAddr,
			})
		}
	}

	if box_docker.State.Running {
		inst.Status.Action = inapi.OpActionRunning
	} else {
		inst.Status.Action = inapi.OpActionStopped
	}

	br.status_update(inst)
}

func (br *BoxKeeper) docker_stats_entry(box_inst *BoxInstance, timo uint32) {

	if box_inst == nil || box_inst.ID == "" || box_inst.Stats == nil {
		return
	}

	if !inapi.OpActionAllow(box_inst.PodOpAction, inapi.OpActionStart) {
		return
	}

	if box_inst.stats_pending {
		return
	}
	box_inst.stats_pending = true

	defer func(box_inst *BoxInstance) {
		box_inst.stats_pending = false
	}(box_inst)

	var (
		timeout  = 3 * time.Second
		ct_stats = make(chan *docker.Stats, 2)
	)

	if err := br.hidocker.Stats(docker.StatsOptions{
		ID:                box_inst.ID,
		Stats:             ct_stats,
		Stream:            false,
		Timeout:           timeout,
		InactivityTimeout: timeout,
	}); err != nil {
		hlog.Printf("error", "docker.Stats %s error %s", box_inst.Name, err.Error())
		return
	}

	stats, ok := <-ct_stats
	if !ok {
		return
	}

	// RAM
	box_inst.Stats.SampleSync("ram/us", timo,
		int64(stats.MemoryStats.Usage))
	box_inst.Stats.SampleSync("ram/cc", timo,
		int64(stats.MemoryStats.Stats.Cache))

	// Networks
	net_io_rs := int64(0)
	net_io_ws := int64(0)
	for _, v := range stats.Networks {
		net_io_rs += int64(v.RxBytes)
		net_io_ws += int64(v.TxBytes)
	}
	box_inst.Stats.SampleSync("net/rs", timo, net_io_rs)
	box_inst.Stats.SampleSync("net/ws", timo, net_io_ws)

	// CPU
	box_inst.Stats.SampleSync("cpu/us", timo,
		int64(stats.CPUStats.CPUUsage.TotalUsage))

	// Storage IO
	fs_rn := int64(0)
	fs_rs := int64(0)
	fs_wn := int64(0)
	fs_ws := int64(0)
	for _, v := range stats.BlkioStats.IOServiceBytesRecursive {
		switch v.Op {
		case "Read":
			fs_rs += int64(v.Value)

		case "Write":
			fs_ws += int64(v.Value)
		}
	}
	for _, v := range stats.BlkioStats.IOServicedRecursive {
		switch v.Op {
		case "Read":
			fs_rn += int64(v.Value)

		case "Write":
			fs_wn += int64(v.Value)
		}
	}
	box_inst.Stats.SampleSync("fs/rn", timo, fs_rn)
	box_inst.Stats.SampleSync("fs/rs", timo, fs_rs)
	box_inst.Stats.SampleSync("fs/wn", timo, fs_wn)
	box_inst.Stats.SampleSync("fs/ws", timo, fs_ws)
}

func (br *BoxKeeper) docker_command(inst *BoxInstance) error {

	hlog.Printf("debug", "hostlet/box run %s", inst.Name)

	br.mu.Lock()
	if br.sets.Has(inst.Name) {
		br.mu.Unlock()
		return nil
	}
	br.sets.Set(inst.Name)
	br.mu.Unlock()

	defer func(inst_name string) {

		br.mu.Lock()
		br.sets.Del(inst_name)
		br.mu.Unlock()

		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet/box Panic %s %v", inst_name, r)
		}

	}(inst.Name)

	if !br.inited {
		return errors.New("Box Server Error")
	}

	// TODO issue
	if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) {
		if err := ipm_prepare(inst); err != nil {
			hlog.Printf("warn", "hostlet/box ipm_prepare %s", err.Error())
			return err
		}
	}

	if inst.PodOpAction == 0 || inst.Spec.Name == "" {
		hlog.Printf("warn", "hostlet/box Error: No Spec Found BOX:%d:%s",
			inst.PodOpAction, inst.Name)
		return errors.New("No Spec Found")
	}

	var err error

	if inst.ID != "" {

		if inst.SpecDesired() && inst.OpActionDesired() {
			return nil
		}

		// Stop current BOX
		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) ||
			inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) {

			if inst.Status.Action == inapi.OpActionRunning {

				// start := time.Now()
				if err = br.hidocker.StopContainer(inst.ID, 10); err != nil {
					inst.Status.Action = inapi.OpActionWarning
				}
				// fmt.Println("stop in", time.Since(start))

				hlog.Printf("info", "hostlet/box stop %s", inst.Name)
			}

			if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) {

				if err = br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
					ID:    inst.ID,
					Force: true,
				}); err == nil {
					inst.Status.Action = inapi.OpActionDestroyed
				} else {
					inst.Status.Action = inapi.OpActionWarning
				}

				hlog.Printf("info", "hostlet/box removed %s", inst.Name)

				inst.ID = ""
			}

			return err
		}

		if !inst.SpecDesired() {

			// js1, _ := json.Encode(inst, " ")

			// hlog.Printf("info", "hostlet/box spec changed %s {{{%s}}}", inst.Name, string(js1))

			if inst.Status.Action == inapi.OpActionRunning {

				hlog.Printf("info", "hostlet/box StopContainer %s", inst.Name)

				if err := br.hidocker.StopContainer(inst.ID, 10); err != nil {
					return err
				}

				inst.Status.Action = inapi.OpActionStopped
			}

			// if inst.Status.Action != inapi.OpActionRunning &&
			// 	inst.Status.Action != inapi.OpActionStopped {

			hlog.Printf("info", "hostlet/box RemoveContainer %s", inst.Name)

			if err := br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err != nil {
				inst.Status.Action = inapi.OpActionWarning
				return err
			}

			inst.ID, inst.Status.Action = "", inapi.OpActionDestroyed
			// } else {
			// 	return
			// }

			time.Sleep(2e8)
		}

	} else {

		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) {

			// hlog.Printf("info", "hostlet/box Skip Stop+NotExist %s", inst.Name)

			inst.Status.Action = inapi.OpActionStopped

			return nil
		}

		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) {
			hlog.Printf("info", "hostlet/box Skip Destroy+NotExist %s", inst.Name)
			inst.Status.Action = inapi.OpActionDestroyed
			return nil
		}
	}

	//
	var (
		dirPodHome = vol_podhome_dir(inst.PodID, inst.RepId)
		initSrc    = in_cf.Prefix + "/bin/ininit"
		initDst    = dirPodHome + "/.sysinner/ininit"
		agentSrc   = in_cf.Prefix + "/bin/inagent"
		agentDst   = dirPodHome + "/.sysinner/inagent"
		bashrcDst  = dirPodHome + "/.bashrc"
		bashrcSrc  = in_cf.Prefix + "/misc/bash/bashrc"
		expPorts   = map[docker.Port]struct{}{}
		bindPorts  = map[docker.Port][]docker.PortBinding{}
	)

	//
	for _, port := range inst.Ports {

		if port.HostPort == 0 {
			port.HostPort, _ = portutil.Free(30000, 40000)
		}

		dockerPort := docker.Port(strconv.Itoa(int(port.BoxPort)) + "/tcp")

		expPorts[dockerPort] = struct{}{} // TODO TCP,UDP...

		bindPorts[dockerPort] = append(bindPorts[docker.Port(strconv.Itoa(int(port.BoxPort)))], docker.PortBinding{
			HostPort: strconv.Itoa(int(port.HostPort)),
			// HostIP:   in_cf.Config.Host.LanAddr.IP(),
		})
	}

	//
	if inst.ID == "" {

		hlog.Printf("info", "hostlet/box CreateContainer %s", inst.Name)

		//
		if err := inutils.FsMakeDir(dirPodHome+"/.sysinner", 2048, 2048, 0750); err != nil {
			hlog.Printf("error", "hostlet/box BOX:%s, FsMakeDir Err:%v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		// hlog.Printf("info", "hostlet/box CreateContainer %s, homefs:%s", inst.Name, dirPodHome)

		imgname, ok := inst.Spec.Image.Options.Get("docker/image/name")
		if !ok {
			hlog.Printf("error", "hostlet/box BOX:%s, No Image Name Found", inst.Name)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		box_docker, err := br.hidocker.CreateContainer(docker.CreateContainerOptions{
			Name: inst.Name,
			Config: &docker.Config{
				Hostname:     inst.Name,
				Memory:       inst.Spec.Resources.MemLimit,
				MemorySwap:   inst.Spec.Resources.MemLimit,
				CPUShares:    inst.Spec.Resources.CpuLimit,
				Cmd:          inst.Spec.Command,
				Image:        imgname.String(),
				ExposedPorts: expPorts,
				Env:          []string{"POD_ID=" + inst.PodID},
				User:         "action",
			},
			HostConfig: &docker.HostConfig{
				Binds:            inst.volume_mounts_export(),
				PortBindings:     bindPorts,
				Memory:           inst.Spec.Resources.MemLimit,
				MemorySwap:       inst.Spec.Resources.MemLimit,
				MemorySwappiness: 0,
				CPUShares:        inst.Spec.Resources.CpuLimit,
				Ulimits: []docker.ULimit{
					{
						Name: "nofile",
						Soft: 50000,
						Hard: 50000,
					},
				},
			},
		})

		if err != nil || box_docker.ID == "" {
			hlog.Printf("info", "hostlet/box CreateContainer %s, Err: %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return errors.New("CreateContainer Error " + err.Error())
		}

		hlog.Printf("info", "hostlet/box CreateContainer %s, DONE", inst.Name)

		// TODO
		inst.ID, inst.Status.Action = box_docker.ID, 0
	}

	if inst.ID != "" &&
		inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) &&
		inst.Status.Action != inapi.OpActionRunning {

		hlog.Printf("info", "hostlet/box StartContainer %s", inst.Name)

		//
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", initSrc, initDst).Output()
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", agentSrc, agentDst).Output()
		exec.Command(cmd_install, bashrcSrc, bashrcDst).Output()

		err = br.hidocker.StartContainer(inst.ID, nil)

		if err != nil {
			hlog.Printf("info", "hostlet/box StartContainer %s, Error %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		hlog.Printf("info", "hostlet/box StartContainer %s, DONE", inst.Name)

		inst.Status.Action = inapi.OpActionRunning

		time.Sleep(1e9)
		br.docker_status_watch_entry(inst.ID)
	} else {
		hlog.Printf("info", "hostlet/box StartContainer %s, SKIP", inst.Name)
	}

	return nil
}
