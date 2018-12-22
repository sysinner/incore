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

package inapi

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"

	"github.com/lynkdb/iomix/skv"
)

const (
	ByteKB int64 = 1024
	ByteMB       = 1024 * ByteKB
	ByteGB       = 1024 * ByteMB
	ByteTB       = 1024 * ByteGB
	BytePB       = 1024 * ByteTB
	ByteEB       = 1024 * BytePB
)

const (
	BoxImageRepoDefault = "sysinner"
)

//
func NsGlobalSysZone(name string) string {
	return fmt.Sprintf("/ing/sys/zone/%s", name)
}

func NsGlobalSysCell(zone_id, cell_id string) string {
	return fmt.Sprintf("/ing/sys/cell/%s/%s", zone_id, cell_id)
}

func NsGlobalSysHost(zone_id, host_id string) string {
	return fmt.Sprintf("/ing/sys/host/%s/%s", zone_id, host_id)
}

func NsGlobalPodSpec(stype, id string) string {
	return fmt.Sprintf("/ing/ps/%s/%s", stype, id)
}

func NsGlobalBoxImage(name, tag string) string {
	return fmt.Sprintf("/ing/bi/%s/%s", name, tag)
}

func NsGlobalPodInstance(pod_id string) string {
	return fmt.Sprintf("/ing/pi/%s", pod_id)
}

func NsGlobalPodInstanceDestroyed(pod_id string) string {
	return fmt.Sprintf("/ing/pid/%s", pod_id)
}

func NsGlobalPodStatus(zone_id, pod_id string) string {
	return fmt.Sprintf("/ing/z/%s/pst/%s", zone_id, pod_id)
}

func NsGlobalAppSpec(spec_id string) string {
	return fmt.Sprintf("/ing/as/%s", spec_id)
}

func NsGlobalAppSpecVersion(spec_id, version string) skv.KvProgKey {
	u32, _ := strconv.Atoi(version)
	if u32 > 65535 {
		u32 = 65535 // TODO
	}
	return skv.NewKvProgKey("ing", "asv", spec_id, uint32(u32))
}

func NsGlobalAppInstance(instance_id string) string {
	return fmt.Sprintf("/ing/ai/%s", instance_id)
}

func NsGlobalAppInstanceDestroyed(instance_id string) string {
	return fmt.Sprintf("/ing/aid/%s", instance_id)
}

func NsGlobalResInstance(meta_name string) string {
	return fmt.Sprintf("/ing/rs/%s", meta_name)
}

func NsGlobalSetQueuePod(zone_id, cell_id, pod_id string) string {
	return fmt.Sprintf("/ing/sq/%s/pod/%s/%s", zone_id, cell_id, pod_id)
}

//
func NsZoneSysInfo(zone_id string) string {
	return fmt.Sprintf("/inz/%s/sys/zone/info", zone_id)
}

func NsZoneSysCell(zone_id, cell_id string) string {
	return fmt.Sprintf("/inz/%s/sys/cell/%s", zone_id, cell_id)
}

func NsZoneSysHost(zone_id, host_id string) string {
	return fmt.Sprintf("/inz/%s/sys/host/%s", zone_id, host_id)
}

func NsZoneSysHostSecretKey(zone_id, host_id string) string {
	return fmt.Sprintf("/inz/%s/sys/hostkey/%s", zone_id, host_id)
}

func NsZoneSysHostStats(zone_id, host_id string, timo uint32) skv.KvProgKey {
	return skv.NewKvProgKey("inz", zone_id, "hs", host_id, timo)
}

func NsZoneSysMasterLeader(zone_id string) string {
	return fmt.Sprintf("/inz/%s/sys/zm/leader", zone_id)
}

func NsZoneSysMasterNode(zone_id, node_id string) string {
	return fmt.Sprintf("/inz/%s/sys/zm/node/%s", zone_id, node_id)
}

func NsZoneSysCellScheduler(zone_id, cell_id string) string {
	return fmt.Sprintf("/inz/%s/sys/job/%s/scheduler", zone_id, cell_id)
}

func NsZonePodInstance(zone_id, pod_id string) string {
	return fmt.Sprintf("/inz/%s/pi/%s", zone_id, pod_id)
}

func NsZonePodInstanceDestroy(zone_id, pod_id string) string {
	return fmt.Sprintf("/inz/%s/pid/%s", zone_id, pod_id)
}

func NsZonePodRepStats(zone_id, pod_id string, repId uint32, name string, timo uint32) skv.KvProgKey {
	return skv.NewKvProgKey(
		"inz", zone_id, "ps",
		NsZonePodOpRepKey(pod_id, repId),
		name, timo,
	)
}

func NsZonePodOpRepKey(pod_id string, repId uint32) string {
	if repId > 65535 {
		repId = 65535
	}
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(repId))
	return fmt.Sprintf("%s.%x", pod_id, bs)
}

var nsZonePodOpRepKeyReg = regexp.MustCompile("^[a-f0-9]{16,20}.[0-9]{4}$")

func NsZonePodOpRepKeyValid(key string) bool {
	return nsZonePodOpRepKeyReg.MatchString(key)
}

func NsZonePodStatus(zone_id, pod_id string) string {
	if len(pod_id) < 8 {
		return fmt.Sprintf("/inz/%s/pst", zone_id)
	}
	return fmt.Sprintf("/inz/%s/pst/%s", zone_id, pod_id)
}

func NsZonePodServiceMap(pod_id string) string {
	return fmt.Sprintf("/inz/ns/ps/%s", pod_id)
}

func NsLocalCacheBoundPod(pod_id string, repId uint32) string {
	if len(pod_id) < 8 {
		return fmt.Sprintf("/inl/c/bp")
	}
	return fmt.Sprintf("/inl/c/bp/%s", NsZonePodOpRepKey(pod_id, repId))
}
