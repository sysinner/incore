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

func (*genericScheduler) Schedule(pod inapi.Pod, hostls inapi.ResHostList) (host_id string, err error) {

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

func (*genericScheduler) ScheduleSets(pod inapi.Pod, hostls inapi.ResHostList) (host_ids []string, err error) {

	//
	if pod.Spec == nil || len(hostls.Items) < 1 {
		return host_ids, errBadArgument
	}

	//
	spec_res := pod.Spec.ResComputeBound()
	if spec_res == nil {
		return host_ids, errBadArgument
	}

	fit_hosts, err := find_hosts_that_fit(pod, hostls)
	if err != nil {
		return host_ids, err
	}

	for _, v := range pod.Operate.Replicas {

		if v.Node != "" {
			host_ids = append(host_ids, v.Node)
			continue
		}

		if len(fit_hosts) == 0 {
			return host_ids, errors.New("No Host Scheduled")
		}

		priority_list, err := prioritizer(fit_hosts)
		if err != nil {
			return host_ids, err
		}

		if len(priority_list) == 0 {
			return host_ids, errors.New("No Host Scheduled")
		}

		host_ids = append(host_ids, priority_list[0].id)

		for j := range fit_hosts {

			if fit_hosts[j].id != priority_list[0].id {
				continue
			}

			fit_hosts[j].cpu_used += spec_res.CpuLimit
			fit_hosts[j].mem_used += spec_res.MemLimit
			if fit_hosts[j].cpu_used+spec_res.CpuLimit > fit_hosts[j].cpu_total ||
				fit_hosts[j].mem_used+spec_res.MemLimit > fit_hosts[j].mem_total {
				fit_hosts = append(fit_hosts[:j], fit_hosts[j+1:]...)
			}

			break
		}
	}

	return host_ids, nil
}

func find_hosts_that_fit(
	pod inapi.Pod,
	hostls inapi.ResHostList,
) ([]*host_fit, error) {

	hosts := []*host_fit{}

	// // TODO
	// sysvol := pod.Volume("system")
	// if sysvol == nil {
	// 	return hosts, errBadArgument
	// }
	docker_on, rkt_on := pod.Spec.DriverBound()

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

		if docker_on && len(v.Spec.ExpDockerVersion) < 2 {
			continue
		}

		if rkt_on && v.Spec.ExpRktVersion == "" {
			continue
		}

		cap_cpu := int64(float64(v.Spec.Capacity.Cpu) * cpu_over_rate)
		cap_mem := int64(float64(v.Spec.Capacity.Mem) * mem_over_rate)

		if (src.CpuLimit+v.Operate.CpuUsed) > cap_cpu ||
			(src.MemLimit+v.Operate.MemUsed) > cap_mem {
			continue // TODO
		}

		hosts = append(hosts, &host_fit{
			id:        v.Meta.Id,
			cpu_used:  v.Operate.CpuUsed,
			cpu_total: cap_cpu,
			mem_used:  v.Operate.MemUsed,
			mem_total: cap_mem,
		})
	}

	return hosts, nil
}

func (*genericScheduler) ScheduleHostValid(entry inapi.ScheduleEntry, host *inapi.ResHost) error {

	cap_cpu := int64(float64(host.Spec.Capacity.Cpu) * cpu_over_rate)
	cap_mem := int64(float64(host.Spec.Capacity.Mem) * mem_over_rate)

	if (entry.Cpu+host.Operate.CpuUsed) > cap_cpu ||
		(entry.Mem+host.Operate.MemUsed) > cap_mem {
		return errors.New("No Res Fit")
	}

	return nil
}
