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

package scheduler

import (
	"errors"

	"github.com/lessos/loscore/losapi"
)

var (
	errBadArgument = errors.New("BadArgument")
)

type genericScheduler struct {
}

func NewScheduler() losapi.Scheduler {
	return &genericScheduler{}
}

func (*genericScheduler) Schedule(pod losapi.Pod, hostls losapi.ResHostList) (host_id string, err error) {

	//
	if pod.Spec == nil || len(hostls.Items) < 1 {
		return "", errBadArgument
	}

	fit_hosts, err := find_hosts_that_fit(pod, hostls)
	if err != nil {
		return "", err
	}

	priority_list, err := prioritizer(fit_hosts)
	if err != nil {
		return "", err
	}

	if len(priority_list) == 0 {
		return "", errors.New("No Host Scheduled")
	}

	return priority_list[0].id, nil
}

func find_hosts_that_fit(
	pod losapi.Pod,
	hostls losapi.ResHostList,
) ([]*host_fit, error) {

	hosts := []*host_fit{}

	// // TODO
	// sysvol := pod.Volume("system")
	// if sysvol == nil {
	// 	return hosts, errBadArgument
	// }

	//
	src := pod.Spec.ResComputeBound()
	if src == nil {
		return hosts, errBadArgument
	}

	for _, v := range hostls.Items {

		if v.Operate == nil ||
			v.Operate.Action != 1 ||
			v.Operate.CellId == "" ||
			v.Operate.CellId != pod.Spec.Cell ||
			v.Spec == nil ||
			v.Spec.Capacity == nil {
			continue
		}

		if (src.CpuLimit+v.Operate.CpuUsed) > int64(v.Spec.Capacity.Cpu) ||
			(src.MemLimit+v.Operate.RamUsed) > int64(v.Spec.Capacity.Memory) {
			continue
		}

		hosts = append(hosts, &host_fit{
			id:        v.Meta.Id,
			cpu_used:  v.Operate.CpuUsed,
			cpu_total: int64(v.Spec.Capacity.Cpu),
			ram_used:  v.Operate.RamUsed,
			ram_total: int64(v.Spec.Capacity.Memory),
		})
	}

	return hosts, nil
}
