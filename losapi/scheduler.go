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

package losapi

// Scheduler is an interface implemented by things that know how to schedule pods
// onto hosts.
type Scheduler interface {
	Schedule(pod Pod, hosts ResHostList) (host_id string, err error)
}

/*
type ScheduleHostOperate struct {
	Id      string      `json:"id"`
	Cell    string      `json:"cell"`
	Action  uint32      `json:"action"`
	CpuUsed int64       `json:"cpu_used,omitempty"`
	RamUsed int64       `json:"ram_used,omitempty"`
	Ports   ArrayUint16 `json:"ports"`
}

type SchudulePodOperate struct {
	Id    string       `json:"id"`
	Host  string       `json:"host"`
	Cpu   int64        `json:"cpu"`
	Ram   int64        `json:"ram"`
	Ports ServicePorts `json:"ports"`
}
*/
