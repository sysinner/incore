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

import (
	"fmt"
)

const (
	ByteKB int64 = 1024
	ByteMB       = 1024 * ByteKB
	ByteGB       = 1024 * ByteMB
	ByteTB       = 1024 * ByteGB
	BytePB       = 1024 * ByteTB
	ByteEB       = 1024 * BytePB
)

//
func NsLocalZoneMasterList() string {
	return "/local/zone-master/list"
}

//
func NsGlobalSysZone(name string) string {
	return fmt.Sprintf("/global/sys/zone/%s", name)
}

func NsGlobalSysCell(zone_id, cell_id string) string {
	return fmt.Sprintf("/global/sys/cell/%s/%s", zone_id, cell_id)
}

//
func NsZoneSysInfo(zone_id string) string {
	return fmt.Sprintf("/%s/sys/zone/info", zone_id)
}

func NsZoneSysCell(zone_id, cell_id string) string {
	return fmt.Sprintf("/%s/sys/cell/%s", zone_id, cell_id)
}

func NsZoneSysHost(zone_id, host_id string) string {
	return fmt.Sprintf("/%s/sys/host/%s", zone_id, host_id)
}

func NsZoneSysHostSecretKey(zone_id, host_id string) string {
	return fmt.Sprintf("/%s/sys/hostkey/%s", zone_id, host_id)
}

func NsZoneSysHostStatus(zone_id, host_id string) string {
	return fmt.Sprintf("/%s/host/%s/status", zone_id, host_id)
}

func NsZoneSysMasterLeader(zone_id string) string {
	return fmt.Sprintf("/%s/sys/zone-master/leader", zone_id)
}

func NsZoneSysMasterNode(zone_id, node_id string) string {
	return fmt.Sprintf("/%s/sys/zone-master/node/%s", zone_id, node_id)
}

func NsZoneSysCellScheduler(zone_id, cell_id string) string {
	return fmt.Sprintf("/%s/sys/job/%s/scheduler", zone_id, cell_id)
}

//
func NsGlobalPodSpec(stype, id string) string {
	return fmt.Sprintf("/global/pod/spec/%s/%s", stype, id)
}

func NsGlobalPodInstance(pod_id string) string {
	return fmt.Sprintf("/global/pod/instance/%s", pod_id)
}

func NsGlobalAppSpec(spec_id string) string {
	return fmt.Sprintf("/global/app/spec/%s", spec_id)
}

func NsGlobalAppInstance(instance_id string) string {
	return fmt.Sprintf("/global/app/instance/%s", instance_id)
}

func NsGlobalResInstance(meta_name string) string {
	return fmt.Sprintf("/global/res/%s", meta_name)
}

//
func NsZonePodSetQueue(zone_id, cell_id, pod_id string) string {
	return fmt.Sprintf("/%s/pod/setq/%s/%s", zone_id, cell_id, pod_id)
}

func NsZonePodInstance(zone_id, pod_id string) string {
	return fmt.Sprintf("/%s/pod/instance/%s", zone_id, pod_id)
}

func NsZoneHostBoundPod(zone_id, host_id, pod_id string) string {
	return fmt.Sprintf("/%s/bound/%s/pod/%s", zone_id, host_id, pod_id)
}

func NsZoneHostBoundPodStatus(zone_id, host_id, pod_id string) string {
	return fmt.Sprintf("/%s/bound/%s/status/%s", zone_id, host_id, pod_id)
}

func NsZonePodServiceMap(pod_id string) string {
	return fmt.Sprintf("/nsz/ps/%s", pod_id)
}
