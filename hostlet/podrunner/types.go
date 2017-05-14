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
	"strings"

	"code.hooto.com/lessos/loscore/config"
	"code.hooto.com/lessos/loscore/losapi"
)

type BoxInstance struct {
	ID          string
	Name        string
	PodID       string
	PodOpAction losapi.OpType
	Spec        losapi.PodSpecBoxBound
	Apps        losapi.AppInstances
	Status      losapi.PodBoxStatus
	Ports       losapi.ServicePorts
	Retry       int
	Env         []losapi.EnvVar
}

func (inst *BoxInstance) SpecDesired() bool {

	//
	if inst.Status.Name == "" {
		return true // wait init
	}

	if inst.Status.Phase == "" {
		return false
	}

	//
	if inst.Spec.Resources.CpuLimit != inst.Status.Resources.CpuLimit ||
		inst.Spec.Resources.MemLimit != inst.Status.Resources.MemLimit {
		return false
	}

	if len(inst.Ports) != len(inst.Status.Ports) {
		return false
	}

	for _, v := range inst.Ports {

		mat := false
		for _, vd := range inst.Status.Ports {

			if v.BoxPort != vd.BoxPort {
				continue
			}

			if v.HostPort > 0 && v.HostPort != vd.HostPort {
				return false
			}

			mat = true
			break
		}

		if !mat {
			return false
		}
	}

	//
	i1, _ := inst.Spec.Image.Options.Get("docker/image/name")
	i2, _ := inst.Status.Image.Options.Get("docker/image/name")
	if i1.String() != i2.String() {
		return false
	}

	//
	if !inst.Spec.Mounts.Equal(inst.Status.Mounts) {
		return false
	}

	if len(inst.Spec.Command) != len(inst.Status.Command) ||
		strings.Join(inst.Spec.Command, " ") != strings.Join(inst.Status.Command, " ") {
		return false
	}

	return true
}

func (inst *BoxInstance) OpActionDesired() bool {

	if (inst.PodOpAction == losapi.OpActionStart && inst.Status.Phase == losapi.OpStatusRunning) ||
		(inst.PodOpAction == losapi.OpActionStop && inst.Status.Phase == losapi.OpStatusStopped) ||
		(inst.PodOpAction == losapi.OpActionDestroy && inst.Status.Phase == losapi.OpStatusDestroyed) {
		return true
	}

	return false
}

func (inst *BoxInstance) volume_mounts_refresh() {

	ls := losapi.VolumeMounts{}

	ls.Sync(losapi.VolumeMount{
		Name:      "home",
		MountPath: "/home/action",
		HostDir:   config.Config.PodHomeDir + "/" + inst.PodID + "-0000/home/action",
		ReadOnly:  false,
	})

	ls.Sync(losapi.VolumeMount{
		Name:      "los/nsz",
		MountPath: "/dev/shm/los/nsz",
		HostDir:   "/dev/shm/los/nsz",
		ReadOnly:  true,
	})

	for _, app := range inst.Apps {

		for _, pkg := range app.Spec.Packages {

			ls.Sync(losapi.VolumeMount{
				Name:      "lpm-" + pkg.Name,
				MountPath: lpm_mountpath(pkg.Name, pkg.Version),
				HostDir:   lpm_hostdir(pkg.Name, pkg.Version, pkg.Release, pkg.Dist, pkg.Arch),
				ReadOnly:  true,
			})
		}
	}

	inst.Spec.Mounts.DiffSync(ls)
}

func (inst *BoxInstance) volume_mounts_export() []string {

	bindVolumes := []string{}

	for _, v := range inst.Spec.Mounts {

		bindVolume := v.HostDir + ":" + v.MountPath
		if v.ReadOnly {
			bindVolume += ":ro"
		}

		bindVolumes = append(bindVolumes, bindVolume)
	}

	return bindVolumes
}
