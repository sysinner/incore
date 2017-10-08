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
	"strings"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
)

const (
	stats_tick      int64  = 5e9
	stats_cycle_buf uint32 = 20
	stats_cycle_log uint32 = 60
)

var (
	vol_podhome_fmt      = "%s/%s.%s/home/action"
	vol_agentsys_dir_fmt = "%s/%s.%s/home/action/.sysinner"
)

func vol_podhome_dir(pod_id string, rep_id uint16) string {
	return fmt.Sprintf(vol_podhome_fmt, config.Config.PodHomeDir,
		pod_id, inutils.Uint16ToHexString(rep_id))
}

func vol_agentsys_dir(pod_id string, rep_id uint16) string {
	return fmt.Sprintf(vol_agentsys_dir_fmt, config.Config.PodHomeDir,
		pod_id, inutils.Uint16ToHexString(rep_id))
}

type BoxInstance struct {
	stats_pending bool
	ID            string
	Name          string
	PodID         string
	RepId         uint16
	PodOpAction   uint32
	Spec          inapi.PodSpecBoxBound
	Apps          inapi.AppInstances
	Status        inapi.PodBoxStatus
	Ports         inapi.ServicePorts
	Retry         int
	Env           []inapi.EnvVar
	Stats         *inapi.TimeStatsFeed
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

	if (inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) && inst.Status.Phase == inapi.OpStatusRunning) ||
		(inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) && inst.Status.Phase == inapi.OpStatusStopped) ||
		(inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) && inst.Status.Phase == inapi.OpStatusDestroyed) {
		return true
	}

	return false
}

func (inst *BoxInstance) volume_mounts_refresh() {

	ls := inapi.VolumeMounts{}

	ls.Sync(inapi.VolumeMount{
		Name:      "home",
		MountPath: "/home/action",
		HostDir:   vol_podhome_dir(inst.PodID, inst.RepId),
		ReadOnly:  false,
	})

	ls.Sync(inapi.VolumeMount{
		Name:      "sysinner/nsz",
		MountPath: "/dev/shm/sysinner/nsz",
		HostDir:   "/dev/shm/sysinner/nsz",
		ReadOnly:  true,
	})

	for _, app := range inst.Apps {

		for _, pkg := range app.Spec.Packages {

			ls.Sync(inapi.VolumeMount{
				Name:      "ipm-" + pkg.Name,
				MountPath: ipm_mountpath(pkg.Name, pkg.Version),
				HostDir:   ipm_hostdir(pkg.Name, pkg.Version, pkg.Release, pkg.Dist, pkg.Arch),
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
