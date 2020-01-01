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
		hit *ScheduleHitItem,
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
	BoxDriver string `json:"box_driver,omitempty" toml:"box_driver,omitempty"`
	CellId    string `json:"cell_id,omitempty" toml:"cell_id,omitempty"`
}

type SchedulePodReplica struct {
	RepId       uint32
	Cpu         int32 // Cores (1 = .1 cores)
	Mem         int32 // MB
	VolSys      int32 // GB
	VolSysAttrs uint32
}

type ScheduleHostList struct {
	Items []*ScheduleHostItem `json:"items,omitempty" toml:"items,omitempty"`
}

type ScheduleHostVolume struct {
	Name  string `json:"name" toml:"name"`
	Total int32  `json:"total" toml:"total"` // GB
	Used  int32  `json:"used" toml:"used"`   // GB
	Attrs uint32 `json:"attrs" toml:"attrs"`
}

type ScheduleHostVolumes []*ScheduleHostVolume

type ScheduleHostItem struct {
	Id               string              `json:"id" toml:"id"`
	OpAction         uint32              `json:"op_action,omitempty" toml:"op_action,omitempty"`
	CellId           string              `json:"cell_id,omitempty" toml:"cell_id,omitempty"`
	CpuTotal         int32               `json:"cpu_total,omitempty" toml:"cpu_total,omitempty"` // Cores (1 = .1 cores)
	CpuUsed          int32               `json:"cpu_used,omitempty" toml:"cpu_used,omitempty"`   // Cores (1 = .1 cores)
	MemTotal         int32               `json:"mem_total,omitempty" toml:"mem_total,omitempty"` // MB
	MemUsed          int32               `json:"mem_used,omitempty" toml:"mem_used,omitempty"`   // MB
	Volumes          ScheduleHostVolumes `json:"volumes" toml:"volumes"`
	BoxDockerVersion string              `json:"box_docker_version,omitempty" toml:"box_docker_version,omitempty"`
	BoxPouchVersion  string              `json:"box_pouch_version,omitempty" toml:"box_pouch_version,omitempty"`
}

type ScheduleOptions struct {
	HostExcludes []string
}

type ScheduleHitVol struct {
	Name string `json:"name" toml:"name"`
	Size int32  `json:"size" toml:"size"`
}

type ScheduleHitItem struct {
	HostId  string
	Volumes []*ScheduleHitVol
	Host    *ScheduleHostItem
}
