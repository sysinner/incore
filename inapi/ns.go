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
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

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

func NsKeyPathLastName(key []byte) string {
	if n := bytes.LastIndexByte(key, '/'); n > 0 && n+1 < len(key) {
		return string(key[n+1:])
	}
	return string(key)
}

func NsKeyPathFilter(path string) []byte {
	var (
		p = strings.Trim(strings.Trim(filepath.Clean(path), "/"), ".")
		n = strings.Count(p, "/") + 1
	)
	if len(path) > 0 && path[len(path)-1] == '/' {
		return []byte(fmt.Sprintf("%d/%s/", n+1, p))
	}
	return []byte(fmt.Sprintf("%d/%s", n, p))
}

// t2
func NsGlobalSysZone(name string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/sys/zone/%s", name))
}
func NsKvGlobalSysZoneDestroyed(name string) []byte {
	return []byte(fmt.Sprintf("ing:sys:zone:%s", name))
}

// t2
func NsGlobalSysCell(zoneId, cellId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/sys/cell/%s/%s", zoneId, cellId))
}

func NsKvGlobalSysCellDestroyed(zoneId, cellId string) []byte {
	return []byte(fmt.Sprintf("ing:sys:cell:%s:%s", zoneId, cellId))
}

// t2
func NsGlobalSysHost(zoneId, hostId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/sys/host/%s/%s", zoneId, hostId))
}

// t2
func NsKvGlobalSysHostDestroyed(zoneId, hostId string) []byte {
	return []byte(fmt.Sprintf("ing:sys:host:rm:%s:%s", zoneId, hostId))
}

// t2
func NsGlobalPodSpec(stype, id string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/ps/%s/%s", stype, id))
}

// t2
func NsGlobalBoxImage(name, tag string) []byte {
	if tag == "" {
		return []byte(fmt.Sprintf("ing:box:image:%s", name))
	}
	return []byte(fmt.Sprintf("ing:box:image:%s:%s", name, tag))
}

// t2
func NsGlobalPodInstance(podId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/pi/%s", podId))
}

// t
func NsKvGlobalPodUserTransfer(podId string) []byte {
	return []byte(fmt.Sprintf("ing:pod:ut:%s", podId))
}

// t2
func NsKvGlobalPodInstanceDestroyed(podId string) []byte {
	return []byte(fmt.Sprintf("ing:pod:rm:%s", podId))
}

// t2
func NsKvGlobalPodStatus(zoneId, podId string) []byte {
	return []byte(fmt.Sprintf("ing:z:%s:pst:%s", zoneId, podId))
}

// t2
func NsGlobalAppSpec(specId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/as/%s", specId))
}

// t
func NsGlobalSysConfig(name string) []byte {
	return []byte(fmt.Sprintf("ing:sys:config:%s", name))
}

func DataAppSpecVersionKey(version string) string {
	if version == "" {
		return ""
	}
	v := NewAppSpecVersion(version)
	if !v.Valid() {
		return ""
	}
	return v.HexString()
}

// t2
func NsKvGlobalAppSpecVersion(specId, version string) []byte {
	return []byte(fmt.Sprintf("ing:asv:%s:%s", specId, DataAppSpecVersionKey(version)))
}

// t3
func NsGlobalAppInstance(appId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/ai/%s", appId))
}

// t2
func NsKvGlobalAppInstanceDestroyed(appId string) []byte {
	return []byte(fmt.Sprintf("ing:app:rm:%s", appId))
}

// t2
func NsGlobalResInstance(subPath string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/ing/rs/%s", subPath))
}

// t
func NsKvGlobalSetQueuePod(zoneId, cellId, podId string) []byte {
	return []byte(fmt.Sprintf("ing:queue:pod:%s:%s:%s", zoneId, cellId, podId))
}

// t2
func NsZoneSysZone(zoneId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/sys/zone/info", zoneId))
}
func NsKvZoneSysZoneDestroyed(zoneId string) []byte {
	return []byte(fmt.Sprintf("inz:%s:sys:zone:info", zoneId))
}

// t2
func NsZoneSysCell(zoneId, cellId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/sys/cell/%s", zoneId, cellId))
}
func NsKvZoneSysCellDestroyed(zoneId, cellId string) []byte {
	return []byte(fmt.Sprintf("inz:%s:sys:cell:%s", zoneId, cellId))
}

// t2
func NsZoneSysHost(zoneId, hostId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/sys/host/%s", zoneId, hostId))
}

// t2
func NsKvZoneSysHostDestroyed(zoneId, hostId string) []byte {
	return []byte(fmt.Sprintf("inz:%s:sys:host:rm:%s", zoneId, hostId))
}

// t2
func NsZoneSysHostSecretKey(zoneId, hostId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/sys/hostkey/%s", zoneId, hostId))
}

// t2
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

// t2
func NsZoneSysMasterNode(zoneId, nodeId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/sys/zm/node/%s", zoneId, nodeId))
}

// t2
func NsZonePodInstance(zoneId, podId string) []byte {
	return NsKeyPathFilter(fmt.Sprintf("/inz/%s/pi/%s", zoneId, podId))
}

// t2
func NsKvZonePodInstanceDestroy(zoneId, podId string) []byte {
	return []byte(fmt.Sprintf("inz:pod:rm:%s:%s", zoneId, podId))
}

// t2
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

// t2
func NsKvZonePodStatus(zoneId, podId string) []byte {
	if len(podId) < 8 {
		return []byte(fmt.Sprintf("inz:pod:status:%s:", zoneId))
	}
	return []byte(fmt.Sprintf("inz:pod:status:%s:%s", zoneId, podId))
}

func NsZoneMailQueue(key string) []byte {
	return []byte(fmt.Sprintf("inz:msg:queue:%s", key))
}

// t2
func NsKvLocalCacheBoundPod(podId string, repId uint32) []byte {
	if len(podId) < 8 {
		return []byte("inl:pod:bind:")
	}
	return []byte(fmt.Sprintf("inl:pod:bind:%s", NsZonePodOpRepKey(podId, repId)))
}
