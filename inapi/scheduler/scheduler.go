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

// Scheduler is an interface implemented by things that know how to schedule pods
// onto hosts.
type Scheduler interface {

	//
	ScheduleHost(
		spec *SchedulePodSpec,
		rep *SchedulePodReplica,
		hostls *ScheduleHostList,
		opts *ScheduleOptions,
	) (
		host *ScheduleHostItem,
		err error,
	)

	//
	ScheduleHostValid(
		host *ScheduleHostItem,
		entry *SchedulePodReplica,
	) (
		err error,
	)
}

type SchedulePodSpec struct {
	BoxDriver string `json:"box_driver,omitempty"`
	CellId    string `json:"cell_id,omitempty"`
}

type SchedulePodReplica struct {
	RepId  uint32
	Cpu    int32 // Cores (1 = .1 cores)
	Mem    int32 // MB
	VolSys int32 // GB
}

type ScheduleHostList struct {
	Items []*ScheduleHostItem `json:"items,omitempty"`
}

type ScheduleHostItem struct {
	Id               string `json:"id"`
	OpAction         uint32 `json:"op_action,omitempty"`
	CellId           string `json:"cell_id,omitempty"`
	CpuTotal         int32  `json:"cpu_total,omitempty"` // Cores (1 = .1 cores)
	CpuUsed          int32  `json:"cpu_used,omitempty"`  // Cores (1 = .1 cores)
	MemTotal         int32  `json:"mem_total,omitempty"` // MB
	MemUsed          int32  `json:"mem_used,omitempty"`  // MB
	VolSys           int32  `json:"vol_sys,omitempty"`   // GB
	BoxDockerVersion string `json:"box_docker_version,omitempty"`
	BoxPouchVersion  string `json:"box_pouch_version,omitempty"`
}

type ScheduleOptions struct {
	HostExcludes []string
}
