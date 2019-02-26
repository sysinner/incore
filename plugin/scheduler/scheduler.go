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

	typeScheduler "github.com/sysinner/incore/inapi/scheduler"
)

var (
	errBadArgument = errors.New("BadArgument")
	cpuOverAlloc   = float64(3.0)
	memOverAlloc   = float64(1.1)
)

type genericScheduler struct {
}

func NewScheduler() typeScheduler.Scheduler {
	return &genericScheduler{}
}

func (*genericScheduler) ScheduleHost(
	spec *typeScheduler.SchedulePodSpec,
	rep *typeScheduler.SchedulePodReplica,
	hostls *typeScheduler.ScheduleHostList,
	opts *typeScheduler.ScheduleOptions,
) (
	host *typeScheduler.ScheduleHostItem,
	err error,
) {

	//
	if spec == nil || rep == nil || len(hostls.Items) < 1 {
		return nil, errBadArgument
	}

	fitHostList, err := findHostListThatFit(spec, rep, hostls, opts)
	if err != nil {
		return nil, err
	}

	priorityList, err := prioritizer(fitHostList)
	if err != nil {
		return nil, err
	}

	if len(priorityList) == 0 {
		return nil, errors.New("No Host Scheduled")
	}

	for _, v := range hostls.Items {
		if v.Id == priorityList[0].id {
			return v, nil
		}
	}

	return nil, errors.New("No Host Scheduled")
}

func findHostListThatFit(
	spec *typeScheduler.SchedulePodSpec,
	rep *typeScheduler.SchedulePodReplica,
	hostls *typeScheduler.ScheduleHostList,
	opts *typeScheduler.ScheduleOptions,
) ([]*hostFit, error) {

	var (
		hostFits     = []*hostFit{}
		hostExcludes = []string{}
		specCpu      = rep.Cpu
		specMem      = rep.Mem
	)

	if opts != nil {
		if len(opts.HostExcludes) > 0 {
			hostExcludes = opts.HostExcludes
		}
	}

	// // TODO
	// sysvol := rep.Volume("system")
	// if sysvol == nil {
	// 	return hostFits, errBadArgument
	// }

	for _, v := range hostls.Items {

		if v.OpAction != 1 ||
			v.CellId == "" ||
			v.CellId != spec.CellId {
			continue
		}

		if len(hostExcludes) > 0 {
			found := false
			for _, hostId := range hostExcludes {
				if hostId == v.Id {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		if (spec.BoxDriver == "docker" && v.BoxDockerVersion != "") ||
			(spec.BoxDriver == "pouch" && v.BoxPouchVersion != "") {
			//
		} else {
			continue
		}

		cpuCap := int32(float64(v.CpuTotal) * cpuOverAlloc)
		memCap := int32(float64(v.MemTotal) * memOverAlloc)

		if (specCpu+v.CpuUsed) > cpuCap ||
			(specMem+v.MemUsed) > memCap {
			continue // TODO
		}

		hostFits = append(hostFits, &hostFit{
			id:        v.Id,
			cpu_used:  v.CpuUsed,
			cpu_total: cpuCap,
			mem_used:  v.MemUsed,
			mem_total: memCap,
		})
	}

	return hostFits, nil
}

func (*genericScheduler) ScheduleHostValid(
	host *typeScheduler.ScheduleHostItem,
	entry *typeScheduler.SchedulePodReplica,
) error {

	cpuCap := int32(float64(host.CpuTotal) * cpuOverAlloc)
	memCap := int32(float64(host.MemTotal) * memOverAlloc)

	if (entry.Cpu+host.CpuUsed) > cpuCap ||
		(entry.Mem+host.MemUsed) > memCap {
		return errors.New("No Res Fit")
	}

	return nil
}
