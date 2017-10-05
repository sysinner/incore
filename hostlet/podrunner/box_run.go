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
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/net/portutil"
	"github.com/lessos/lessgo/types"

	in_cf "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	timeout = time.Second * 10
)

func (br *BoxKeeper) status_watcher() {

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

			c7r, err := br.hidocker.InspectContainer(vc.ID)
			if err != nil || c7r == nil {
				continue
			}

			pod_id, rep_id, box_name := box_inst_name_parse(c7r.Config.Hostname)
			if pod_id == "" {
				continue
			}

			inst := &BoxInstance{
				ID:    vc.ID,
				Name:  c7r.Config.Hostname,
				PodID: pod_id,
				RepId: rep_id,
				Status: inapi.PodBoxStatus{
					Name:    box_name,
					Started: types.MetaTimeSet(c7r.State.StartedAt.UTC()),
					Updated: types.MetaTimeNow(),
					Resources: inapi.PodBoxStatusResCompute{
						CpuLimit: c7r.HostConfig.CPUShares,
						MemLimit: c7r.HostConfig.Memory,
					},
					Image: inapi.PodBoxStatusImage{
						Driver: inapi.PodSpecBoxImageDocker,
					},
					Command: c7r.Config.Cmd,
				},
			}
			inst.Status.Image.Options.Set("docker/image/name", c7r.Config.Image)

			//
			for _, cm := range c7r.Mounts {

				inst.Status.Mounts.Sync(inapi.VolumeMount{
					MountPath: cm.Destination,
					HostDir:   cm.Source,
					ReadOnly:  !cm.RW,
				})
			}

			// TODO
			if len(c7r.HostConfig.PortBindings) > 0 {

				for c7rPortKey, c7rPorts := range c7r.HostConfig.PortBindings {

					if len(c7rPorts) < 1 {
						continue
					}

					ps := strings.Split(string(c7rPortKey), "/")
					if len(ps) != 2 {
						continue
					}

					var (
						boxPort, _  = strconv.Atoi(ps[0])
						hostPort, _ = strconv.Atoi(c7rPorts[0].HostPort)
					)

					inst.Status.Ports.Sync(inapi.ServicePort{
						BoxPort:  uint16(boxPort),
						HostPort: uint16(hostPort),
						// Protocol: inapi.ProtocolTCP, //
						// HostIP:   conf.Config.HostAddr,
					})
				}
			}

			if c7r.State.Running {
				inst.Status.Phase = inapi.OpStatusRunning
			} else {
				inst.Status.Phase = inapi.OpStatusStopped
			}

			br.status_update(inst)
		}

		if !br.inited {
			time.Sleep(2e9)
			br.inited = true
		}

		// Diff and retry
		for _, inst := range box_keeper.instances {

			if inst.PodOpAction == 0 {
				continue
			}

			if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) {

				if inst.SpecDesired() {
					continue
				}
			}

			if inst.OpActionDesired() {
				continue
			}

			if len(br.actions) < 100 {
				inst.Retry++
				br.actions <- inst.Name
			}

			hlog.Printf("error", "nodelet/box Retry %s:%d", inst.Name, inst.Retry)
		}

		time.Sleep(2e9)
	}
}

func (br *BoxKeeper) run(inst_name string) error {

	hlog.Printf("debug", "nodelet/box run %s", inst_name)

	br.mu.Lock()
	if br.sets.Contain(inst_name) {
		br.mu.Unlock()
		return nil
	}
	br.sets.Insert(inst_name)
	br.mu.Unlock()

	defer func(inst_name string) {

		br.mu.Lock()
		br.sets.Remove(inst_name)
		br.mu.Unlock()

		if r := recover(); r != nil {
			hlog.Printf("error", "nodelet/box Panic %s %v", inst_name, r)
		}

	}(inst_name)

	if !br.inited {

		if len(br.actions) < 100 {
			time.Sleep(2e9)
			br.actions <- inst_name
		}

		return errors.New("Box Server Error")
	}

	inst, ok := box_keeper.instances[inst_name]
	if !ok {
		return errors.New("Box Not Found")
	}

	// TODO issue
	if err := ipm_prepare(inst); err != nil {
		hlog.Printf("warn", "nodelet/box ipm_prepare %s", err.Error())
		return err
	}

	if inst.PodOpAction == 0 || inst.Spec.Name == "" {
		hlog.Printf("warn", "nodelet/box Error: No Spec Found BOX:%d:%s",
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

			if inst.Status.Phase == inapi.OpStatusRunning {

				// start := time.Now()
				if err = br.hidocker.StopContainer(inst.ID, 10); err != nil {
					inst.Status.Phase = inapi.OpStatusFailed
				}
				// fmt.Println("stop in", time.Since(start))

				hlog.Printf("info", "nodelet/box stop %s", inst.Name)
			}

			if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) {

				if err = br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
					ID:    inst.ID,
					Force: true,
				}); err == nil {
					inst.Status.Phase = inapi.OpStatusDestroyed
				} else {
					inst.Status.Phase = inapi.OpStatusFailed
				}

				hlog.Printf("info", "nodelet/box removed %s", inst.Name)

				inst.ID = ""
			}

			return err
		}

		if !inst.SpecDesired() {

			hlog.Printf("info", "nodelet/box spec changed %s", inst.Name)

			if inst.Status.Phase == inapi.OpStatusRunning {

				hlog.Printf("info", "nodelet/box StopContainer %s", inst.Name)

				if err := br.hidocker.StopContainer(inst.ID, 10); err != nil {
					return err
				}

				inst.Status.Phase = inapi.OpStatusStopped
			}

			// if inst.Status.Phase != inapi.OpStatusRunning &&
			// 	inst.Status.Phase != inapi.OpStatusStopped {

			hlog.Printf("info", "nodelet/box RemoveContainer %s", inst.Name)

			if err := br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err != nil {
				inst.Status.Phase = inapi.OpStatusFailed
				return err
			}

			inst.ID, inst.Status.Phase = "", inapi.OpStatusDestroyed
			// } else {
			// 	return
			// }

			time.Sleep(2e8)
		}

	} else {

		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) {

			// hlog.Printf("info", "nodelet/box Skip Stop+NotExist %s", inst.Name)

			inst.Status.Phase = inapi.OpStatusStopped

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

		hlog.Printf("info", "nodelet/box CreateContainer %s", inst.Name)

		//
		if err := inutils.FsMakeDir(dirPodHome+"/.sysinner", 2048, 2048, 0750); err != nil {
			hlog.Printf("error", "nodelet/box BOX:%s, FsMakeDir Err:%v", inst.Name, err)
			inst.Status.Phase = inapi.OpStatusFailed
			return err
		}
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", initSrc, initDst).Output()
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", agentSrc, agentDst).Output()
		exec.Command(cmd_install, bashrcSrc, bashrcDst).Output()

		// hlog.Printf("info", "nodelet/box CreateContainer %s, homefs:%s", inst.Name, dirPodHome)

		imgname, ok := inst.Spec.Image.Options.Get("docker/image/name")
		if !ok {
			hlog.Printf("error", "nodelet/box BOX:%s, No Image Name Found", inst.Name)
			inst.Status.Phase = inapi.OpStatusFailed
			return err
		}

		c7r, err := br.hidocker.CreateContainer(docker.CreateContainerOptions{
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
			},
		})

		if err != nil || c7r.ID == "" {
			hlog.Printf("info", "nodelet/box CreateContainer %s, Err: %v", inst.Name, err)
			inst.Status.Phase = inapi.OpStatusFailed
			return errors.New("CreateContainer Error " + err.Error())
		}

		hlog.Printf("info", "nodelet/box CreateContainer %s, DONE", inst.Name)

		// TODO
		inst.ID, inst.Status.Phase = c7r.ID, ""
	}

	if inst.ID != "" &&
		inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) &&
		inst.Status.Phase != inapi.OpStatusRunning {

		hlog.Printf("info", "nodelet/box StartContainer %s", inst.Name)

		err = br.hidocker.StartContainer(inst.ID, nil)

		if err != nil {
			hlog.Printf("info", "nodelet/box StartContainer %s, Error %v", inst.Name, err)
			inst.Status.Phase = inapi.OpStatusFailed
			return err
		}

		hlog.Printf("info", "nodelet/box StartContainer %s, DONE", inst.Name)

		inst.Status.Phase = inapi.OpStatusRunning
	} else {
		hlog.Printf("info", "nodelet/box StartContainer %s, SKIP", inst.Name)
	}

	return nil
}
