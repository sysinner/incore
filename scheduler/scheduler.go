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

package scheduler

import (
	"errors"

	"github.com/sysinner/incore/inapi"
)

var (
	errBadArgument = errors.New("BadArgument")
	cpu_over_rate  = float64(3.0)
	mem_over_rate  = float64(1.1)
)

type genericScheduler struct {
}

func NewScheduler() inapi.Scheduler {
	return &genericScheduler{}
}

func (*genericScheduler) Schedule(
	spec *inapi.PodSpecBound,
	rep *inapi.PodOperateReplica,
	hostls inapi.ResHostList,
	opts *inapi.ScheduleOptions,
) (host_id string, err error) {

	//
	if spec == nil || len(hostls.Items) < 1 {
		return "", errBadArgument
	}

	fitHostList, err := findHostListThatFit(spec, rep, hostls, opts)
	if err != nil {
		return "", err
	}

	priorityList, err := prioritizer(fitHostList)
	if err != nil {
		return "", err
	}

	if len(priorityList) == 0 {
		return "", errors.New("No Host Scheduled")
	}

	return priorityList[0].id, nil
}

func findHostListThatFit(
	spec *inapi.PodSpecBound,
	rep *inapi.PodOperateReplica,
	hostls inapi.ResHostList,
	opts *inapi.ScheduleOptions,
) ([]*hostFit, error) {

	var (
		hosts        = []*hostFit{}
		hostExcludes = []string{}
	)

	if opts != nil {
		if len(opts.HostExcludes) > 0 {
			hostExcludes = opts.HostExcludes
		}
	}

	// // TODO
	// sysvol := rep.Volume("system")
	// if sysvol == nil {
	// 	return hosts, errBadArgument
	// }
	docker_on, rkt_on, pouch_on := spec.DriverBound()

	specCpu := int64(rep.ResCpu) * 200
	specMem := int64(rep.ResMem) * inapi.ByteMB

	for _, v := range hostls.Items {

		if v.Operate == nil ||
			v.Operate.Action != 1 ||
			v.Operate.CellId == "" ||
			v.Operate.CellId != spec.Cell ||
			v.Spec == nil ||
			v.Spec.Capacity == nil {
			continue
		}

		if len(hostExcludes) > 0 {
			found := false
			for _, hostId := range hostExcludes {
				if hostId == v.Meta.Id {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		if docker_on && len(v.Spec.ExpDockerVersion) < 2 {
			continue
		}

		if rkt_on && v.Spec.ExpRktVersion == "" {
			continue
		}

		if pouch_on && v.Spec.ExpPouchVersion == "" {
			continue
		}

		cpu_cap := int64(float64(v.Spec.Capacity.Cpu) * cpu_over_rate)
		mem_cap := int64(float64(v.Spec.Capacity.Mem) * mem_over_rate)

		if (specCpu+v.Operate.CpuUsed) > cpu_cap ||
			(specMem+v.Operate.MemUsed) > mem_cap {
			continue // TODO
		}

		hosts = append(hosts, &hostFit{
			id:        v.Meta.Id,
			cpu_used:  v.Operate.CpuUsed,
			cpu_total: cpu_cap,
			mem_used:  v.Operate.MemUsed,
			mem_total: mem_cap,
		})
	}

	return hosts, nil
}

func (*genericScheduler) ScheduleHostValid(host *inapi.ResHost, entry inapi.ScheduleEntry) error {

	cpu_cap := int64(float64(host.Spec.Capacity.Cpu) * cpu_over_rate)
	mem_cap := int64(float64(host.Spec.Capacity.Mem) * mem_over_rate)

	if (entry.Cpu+host.Operate.CpuUsed) > cpu_cap ||
		(entry.Mem+host.Operate.MemUsed) > mem_cap {
		return errors.New("No Res Fit")
	}

	return nil
}
