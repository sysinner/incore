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

	"github.com/sysinner/incore/inutils"
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

func NsGlobalSysCell(zoneId, cellId string) string {
	return fmt.Sprintf("/ing/sys/cell/%s/%s", zoneId, cellId)
}

func NsGlobalSysHost(zoneId, hostId string) string {
	return fmt.Sprintf("/ing/sys/host/%s/%s", zoneId, hostId)
}

func NsGlobalPodSpec(stype, id string) string {
	return fmt.Sprintf("/ing/ps/%s/%s", stype, id)
}

func NsGlobalBoxImage(name, tag string) []byte {
	if tag == "" {
		return []byte(fmt.Sprintf("ing:box:image:%s", name))
	}
	return []byte(fmt.Sprintf("ing:box:image:%s:%s", name, tag))
}

func NsGlobalPodInstance(podId string) string {
	return fmt.Sprintf("/ing/pi/%s", podId)
}

func NsKvGlobalPodUserTransfer(podId string) []byte {
	return []byte(fmt.Sprintf("ing:pod:ut:%s", podId))
}

func NsKvGlobalPodInstanceDestroyed(podId string) []byte {
	return []byte(fmt.Sprintf("ing:pod:rm:%s", podId))
}

func NsKvGlobalPodStatus(zoneId, podId string) []byte {
	return []byte(fmt.Sprintf("ing:z:%s:pst:%s", zoneId, podId))
}

func NsGlobalAppSpec(specId string) string {
	return fmt.Sprintf("/ing/as/%s", specId)
}

func NsGlobalSysConfig(name string) []byte {
	return []byte(fmt.Sprintf("ing:sys:config:%s", name))
}

func DataAppSpecVersionKey(version string) string {
	if version == "" {
		return ""
	}
	u32, _ := strconv.Atoi(version)
	return fmt.Sprintf("%s.%s",
		inutils.Uint32ToHexString(0), inutils.Uint32ToHexString(uint32(u32)))
}

func NsKvGlobalAppSpecVersion(specId, version string) []byte {
	return []byte(fmt.Sprintf("ing:asv:%s:%s", specId, DataAppSpecVersionKey(version)))
}

func NsGlobalAppInstance(appId string) string {
	return fmt.Sprintf("/ing/ai/%s", appId)
}

func NsKvGlobalAppInstanceDestroyed(appId string) []byte {
	return []byte(fmt.Sprintf("ing:app:rm:%s", appId))
}

func NsGlobalResInstance(metaName string) string {
	return fmt.Sprintf("/ing/rs/%s", metaName)
}

func NsKvGlobalSetQueuePod(zoneId, cellId, podId string) []byte {
	return []byte(fmt.Sprintf("ing:queue:pod:%s:%s:%s", zoneId, cellId, podId))
}

//
func NsZoneSysInfo(zoneId string) string {
	return fmt.Sprintf("/inz/%s/sys/zone/info", zoneId)
}

func NsZoneSysCell(zoneId, cellId string) string {
	return fmt.Sprintf("/inz/%s/sys/cell/%s", zoneId, cellId)
}

func NsZoneSysHost(zoneId, hostId string) string {
	return fmt.Sprintf("/inz/%s/sys/host/%s", zoneId, hostId)
}

func NsZoneSysHostSecretKey(zoneId, hostId string) string {
	return fmt.Sprintf("/inz/%s/sys/hostkey/%s", zoneId, hostId)
}

func NsKvZoneSysHostStats(zoneId, hostId string, timo uint32) []byte {
	if timo == 0 {
		return []byte(fmt.Sprintf("inz:sys:host:stats:%s:%s:",
			zoneId, hostId,
		))
	}
	return []byte(fmt.Sprintf("inz:sys:host:stats:%s:%s:%s",
		zoneId, hostId, inutils.Uint32ToHexString(timo),
	))
}

func NsKvZoneSysMasterLeader(zoneId string) []byte {
	return []byte(fmt.Sprintf("inz:sys:zm:leader:%s", zoneId))
}

func NsZoneSysMasterNode(zoneId, nodeId string) string {
	return fmt.Sprintf("/inz/%s/sys/zm/node/%s", zoneId, nodeId)
}

func NsZonePodInstance(zoneId, podId string) string {
	return fmt.Sprintf("/inz/%s/pi/%s", zoneId, podId)
}

func NsKvZonePodInstanceDestroy(zoneId, podId string) []byte {
	return []byte(fmt.Sprintf("inz:pod:rm:%s:%s", zoneId, podId))
}

func NsKvZonePodRepStats(zoneId, podId string, repId uint32, name string, timo uint32) []byte {
	if timo == 0 {
		return []byte(fmt.Sprintf("inz:pod:stats:%s:%s:%s:",
			zoneId, NsZonePodOpRepKey(podId, repId), name))
	}
	return []byte(fmt.Sprintf("inz:pod:stats:%s:%s:%s:%s",
		zoneId, NsZonePodOpRepKey(podId, repId), name, inutils.Uint32ToHexString(timo)),
	)
}

func NsZonePodOpRepKey(podId string, repId uint32) string {
	if repId > 65535 {
		repId = 65535
	}
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(repId))
	return fmt.Sprintf("%s.%x", podId, bs)
}

var nsZonePodOpRepKeyReg = regexp.MustCompile("^[a-f0-9]{16,20}.[0-9]{4}$")

func NsZonePodOpRepKeyValid(key string) bool {
	return nsZonePodOpRepKeyReg.MatchString(key)
}

func NsKvZonePodStatus(zoneId, podId string) []byte {
	if len(podId) < 8 {
		return []byte(fmt.Sprintf("inz:pod:status:%s:", zoneId))
	}
	return []byte(fmt.Sprintf("inz:pod:status:%s:%s", zoneId, podId))
}

func NsKvLocalCacheBoundPod(podId string, repId uint32) []byte {
	if len(podId) < 8 {
		return []byte("inl:pod:bind:")
	}
	return []byte(fmt.Sprintf("inl:pod:bind:%s", NsZonePodOpRepKey(podId, repId)))
}
