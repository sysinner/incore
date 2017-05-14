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
	"github.com/lessos/lessgo/logger"
	"github.com/lessos/lessgo/net/portutil"
	"github.com/lessos/lessgo/types"

	los_cf "code.hooto.com/lessos/loscore/config"
	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/losutils"
	los_sts "code.hooto.com/lessos/loscore/status"
)

var (
	timeout = time.Second * 10
)

func (br *BoxKeeper) status_watcher() {

	br.inited = false

	for {

		time.Sleep(2e9)

		if los_sts.Host.Meta.Id == "" {
			continue
		}

		if br.hidocker == nil {

			for {

				br.hidocker, err = docker.NewClient(docker_unixsock)
				if err != nil {
					logger.Printf("fatal", "Can not connect to Docker Server, Error: %s", err)
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
			logger.Printf("error", "hidocker.ListContainers Error %v", err)
			br.inited = false
			continue
		}

		for _, vc := range rsc {

			c7r, err := br.hidocker.InspectContainer(vc.ID)
			if err != nil || c7r == nil {
				continue
			}

			pod_id, _, box_name := box_inst_name_parse(c7r.Config.Hostname)
			if pod_id == "" {
				continue
			}

			inst := &BoxInstance{
				ID:    vc.ID,
				Name:  c7r.Config.Hostname,
				PodID: pod_id,
				Status: losapi.PodBoxStatus{
					Name:    box_name,
					Started: types.MetaTimeSet(c7r.State.StartedAt.UTC()),
					Updated: types.MetaTimeNow(),
					Resources: losapi.PodBoxStatusResCompute{
						CpuLimit: c7r.HostConfig.CPUShares,
						MemLimit: c7r.HostConfig.Memory,
					},
					Image: losapi.PodBoxStatusImage{
						Driver: losapi.PodSpecBoxImageDocker,
					},
					Command: c7r.Config.Cmd,
				},
			}
			inst.Status.Image.Options.Set("docker/image/name", c7r.Config.Image)

			//
			for _, cm := range c7r.Mounts {

				inst.Status.Mounts.Sync(losapi.VolumeMount{
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

					inst.Status.Ports.Sync(losapi.ServicePort{
						BoxPort:  uint16(boxPort),
						HostPort: uint16(hostPort),
						// Protocol: losapi.ProtocolTCP, //
						// HostIP:   conf.Config.HostAddr,
					})
				}
			}

			if c7r.State.Running {
				inst.Status.Phase = losapi.OpStatusRunning
			} else {
				inst.Status.Phase = losapi.OpStatusStopped
			}

			br.status_update(inst)
		}

		if !br.inited {
			time.Sleep(2e9)
			br.inited = true
		}

		// Diff and retry
		for _, inst := range box_keeper.instances {

			if inst.PodOpAction == "" {
				continue
			}

			if inst.PodOpAction == losapi.OpActionStart {

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

			logger.Printf("error", "nodelet/box Retry %s:%d", inst.Name, inst.Retry)
		}

		time.Sleep(2e9)
	}
}

func (br *BoxKeeper) run(inst_name string) error {

	logger.Printf("debug", "nodelet/box run %s", inst_name)

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
			logger.Printf("error", "nodelet/box Panic %s %v", inst_name, r)
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
	if err := lpm_prepare(inst); err != nil {
		logger.Printf("warn", "nodelet/box lpm_prepare %s", err.Error())
		return err
	}

	if inst.PodOpAction == "" || inst.Spec.Name == "" {
		logger.Printf("warn", "nodelet/box Error: No Spec Found BOX:%s", inst.Name)
		return errors.New("No Spec Found")
	}

	var err error

	if inst.ID != "" {

		if inst.SpecDesired() && inst.OpActionDesired() {
			return nil
		}

		// Stop current BOX
		if inst.PodOpAction == losapi.OpActionStop ||
			inst.PodOpAction == losapi.OpActionDestroy {

			if inst.Status.Phase == losapi.OpStatusRunning {

				// start := time.Now()
				if err = br.hidocker.StopContainer(inst.ID, 10); err != nil {
					inst.Status.Phase = losapi.OpStatusFailed
				}
				// fmt.Println("stop in", time.Since(start))

				logger.Printf("info", "nodelet/box stop %s", inst.Name)
			}

			if inst.PodOpAction == losapi.OpActionDestroy {

				if err = br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
					ID:    inst.ID,
					Force: true,
				}); err == nil {
					inst.Status.Phase = losapi.OpStatusDestroyed
				} else {
					inst.Status.Phase = losapi.OpStatusFailed
				}

				logger.Printf("info", "nodelet/box removed %s", inst.Name)

				inst.ID = ""
			}

			return err
		}

		if !inst.SpecDesired() {

			logger.Printf("info", "nodelet/box spec changed %s", inst.Name)

			if inst.Status.Phase == losapi.OpStatusRunning {

				logger.Printf("info", "nodelet/box StopContainer %s", inst.Name)

				if err := br.hidocker.StopContainer(inst.ID, 10); err != nil {
					return err
				}

				inst.Status.Phase = losapi.OpStatusStopped
			}

			// if inst.Status.Phase != losapi.OpStatusRunning &&
			// 	inst.Status.Phase != losapi.OpStatusStopped {

			logger.Printf("info", "nodelet/box RemoveContainer %s", inst.Name)

			if err := br.hidocker.RemoveContainer(docker.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err != nil {
				inst.Status.Phase = losapi.OpStatusFailed
				return err
			}

			inst.ID, inst.Status.Phase = "", losapi.OpStatusDestroyed
			// } else {
			// 	return
			// }

			time.Sleep(2e8)
		}

	} else {

		if inst.PodOpAction == losapi.OpActionStop {

			// logger.Printf("info", "nodelet/box Skip Stop+NotExist %s", inst.Name)

			inst.Status.Phase = losapi.OpStatusStopped

			return nil
		}
	}

	//
	var (
		dirPod     = los_cf.Config.PodHomeDir + "/" + inst.PodID + "-0000"
		dirPodHome = dirPod + "/home/action"
		initSrc    = los_cf.Prefix + "/bin/lpinit"
		initDst    = dirPodHome + "/.los/lpinit"
		agentSrc   = los_cf.Prefix + "/bin/lpagent"
		agentDst   = dirPodHome + "/.los/lpagent"
		bashrcDst  = dirPodHome + "/.bashrc"
		bashrcSrc  = los_cf.Prefix + "/misc/bash/bashrc"
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
			// HostIP:   los_cf.Config.Host.LanAddr.IP(),
		})
	}

	//
	if inst.ID == "" {

		logger.Printf("info", "nodelet/box CreateContainer %s", inst.Name)

		//
		if err := losutils.FsMakeDir(dirPodHome+"/.los", 2048, 2048, 0750); err != nil {
			logger.Printf("error", "nodelet/box BOX:%s, FsMakeDir Err:%v", inst.Name, err)
			inst.Status.Phase = losapi.OpStatusFailed
			return err
		}
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", initSrc, initDst).Output()
		exec.Command(cmd_install, "-m", "755", "-g", "root", "-o", "root", agentSrc, agentDst).Output()
		exec.Command(cmd_install, bashrcSrc, bashrcDst).Output()

		// logger.Printf("info", "nodelet/box CreateContainer %s, homefs:%s", inst.Name, dirPodHome)

		imgname, ok := inst.Spec.Image.Options.Get("docker/image/name")
		if !ok {
			logger.Printf("error", "nodelet/box BOX:%s, No Image Name Found", inst.Name)
			inst.Status.Phase = losapi.OpStatusFailed
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
			logger.Printf("info", "nodelet/box CreateContainer %s, Err: %v", inst.Name, err)
			inst.Status.Phase = losapi.OpStatusFailed
			return errors.New("CreateContainer Error " + err.Error())
		}

		logger.Printf("info", "nodelet/box CreateContainer %s, DONE", inst.Name)

		// TODO
		inst.ID, inst.Status.Phase = c7r.ID, ""
	}

	if inst.ID != "" &&
		inst.PodOpAction == losapi.OpActionStart &&
		inst.Status.Phase != losapi.OpStatusRunning {

		logger.Printf("info", "nodelet/box StartContainer %s", inst.Name)

		err = br.hidocker.StartContainer(inst.ID, nil)

		if err != nil {
			logger.Printf("info", "nodelet/box StartContainer %s, Error %v", inst.Name, err)
			inst.Status.Phase = losapi.OpStatusFailed
			return err
		}

		logger.Printf("info", "nodelet/box StartContainer %s, DONE", inst.Name)

		inst.Status.Phase = losapi.OpStatusRunning
	} else {
		logger.Printf("info", "nodelet/box StartContainer %s, SKIP", inst.Name)
	}

	return nil
}
