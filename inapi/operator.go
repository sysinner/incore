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
	"fmt"
	"sync"
	"time"
)

var (
	OpActionStart     uint32 = 1 << 1
	OpActionRunning   uint32 = 1 << 2
	OpActionStop      uint32 = 1 << 3
	OpActionStopped   uint32 = 1 << 4
	OpActionDestroy   uint32 = 1 << 5
	OpActionDestroyed uint32 = 1 << 6
	OpActionMigrate   uint32 = 1 << 7
	OpActionMigrated  uint32 = 1 << 8
	OpActionFailover  uint32 = 1 << 9
	OpActionPending   uint32 = 1 << 11
	OpActionWarning   uint32 = 1 << 12
	OpActionRestart   uint32 = 1 << 23
	OpActionResFree   uint32 = 1 << 24
	OpActionHang      uint32 = 1 << 25
	OpActionUnbound   uint32 = 1 << 26
	OpActionForce     uint32 = 1 << 27
	oplogListMu       sync.RWMutex
	oplogSetsMu       sync.RWMutex

	OpActionDesires = []uint32{
		OpActionStart, OpActionRunning,
		OpActionStop, OpActionStopped,
		OpActionDestroy, OpActionDestroyed,
		OpActionMigrate, OpActionMigrated,
	}
)

func OpActionValid(op uint32) bool {
	return OpActionAllow(
		OpActionStart|OpActionRunning|
			OpActionStop|OpActionStopped|
			OpActionDestroy|OpActionDestroyed|
			OpActionMigrate|
			OpActionFailover|
			OpActionPending|OpActionWarning|
			OpActionRestart,
		op,
	)
}

func OpActionStatusClean(opCtr, opStatus uint32) uint32 {
	for i := 0; i < len(OpActionDesires); i += 2 {
		if OpActionAllow(opStatus, OpActionDesires[i+1]) &&
			!OpActionAllow(opCtr, OpActionDesires[i]) {
			opStatus = OpActionRemove(opStatus, OpActionDesires[i+1])
		}
	}
	return opStatus
}

func OpActionDesire(opbase, op uint32) uint32 {
	opDes := uint32(0)
	for i := 0; i < len(OpActionDesires); i += 2 {
		if OpActionAllow(opbase, OpActionDesires[i]) &&
			OpActionAllow(op, OpActionDesires[i+1]) {
			opDes = opDes | OpActionDesires[i+1]
		}
	}
	return opDes
}

func OpActionAllow(opbase, op uint32) bool {
	return (op & opbase) == op
}

func OpActionRemove(opbase, op uint32) uint32 {
	return (opbase | op) - (op)
}

func OpActionAppend(opbase, op uint32) uint32 {
	return (opbase | op)
}

func OpActionControlFilter(opbase uint32) uint32 {

	if OpActionAllow(opbase, OpActionDestroy) {
		opbase = OpActionRemove(opbase, OpActionStart|OpActionStop)
	} else if OpActionAllow(opbase, OpActionStop) {
		opbase = OpActionRemove(opbase, OpActionStart)
	} else if OpActionAllow(opbase, OpActionStart) {
		opbase = OpActionRemove(opbase, OpActionStop)
	}

	return opbase
}

func OpActionString(action uint32) string {

	if OpActionAllow(action, OpActionStart) {
		return "start"
	}

	if OpActionAllow(action, OpActionRunning) {
		return "running"
	}

	if OpActionAllow(action, OpActionStop) {
		return "stop"
	}

	if OpActionAllow(action, OpActionStopped) {
		return "stopped"
	}

	if OpActionAllow(action, OpActionDestroy) {
		return "destroy"
	}

	if OpActionAllow(action, OpActionDestroyed) {
		return "destroyed"
	}

	if OpActionAllow(action, OpActionMigrate) {
		return "migrate"
	}

	if OpActionAllow(action, OpActionMigrated) {
		return "migrated"
	}

	if OpActionAllow(action, OpActionFailover) {
		return "failover"
	}

	if OpActionAllow(action, OpActionPending) {
		return "pending"
	}

	if OpActionAllow(action, OpActionWarning) {
		return "warning"
	}

	if OpActionAllow(action, OpActionResFree) {
		return "resfree"
	}

	if OpActionAllow(action, OpActionHang) {
		return "hang"
	}

	if OpActionAllow(action, OpActionForce) {
		return "force"
	}

	return ""
}

func OpActionStrings(action uint32) []string {

	s := []string{}

	if OpActionAllow(action, OpActionStart) {
		s = append(s, "start")
	}

	if OpActionAllow(action, OpActionRunning) {
		s = append(s, "running")
	}

	if OpActionAllow(action, OpActionStop) {
		s = append(s, "stop")
	}

	if OpActionAllow(action, OpActionStopped) {
		s = append(s, "stopped")
	}

	if OpActionAllow(action, OpActionDestroy) {
		s = append(s, "destroy")
	}

	if OpActionAllow(action, OpActionDestroyed) {
		s = append(s, "destroyed")
	}

	if OpActionAllow(action, OpActionMigrate) {
		s = append(s, "migrate")
	}

	if OpActionAllow(action, OpActionMigrated) {
		s = append(s, "migrated")
	}

	if OpActionAllow(action, OpActionFailover) {
		s = append(s, "failover")
	}

	if OpActionAllow(action, OpActionPending) {
		s = append(s, "pending")
	}

	if OpActionAllow(action, OpActionWarning) {
		s = append(s, "warning")
	}

	if OpActionAllow(action, OpActionResFree) {
		s = append(s, "resfree")
	}

	if OpActionAllow(action, OpActionHang) {
		s = append(s, "hang")
	}

	if OpActionAllow(action, OpActionForce) {
		s = append(s, "force")
	}

	return s
}

const (
	PbOpLogOK    = "ok"
	PbOpLogInfo  = "info"
	PbOpLogWarn  = "warn"
	PbOpLogError = "error"

	NsOpLogZoneRepMigrateAlloc       = "zm/rep-migrate/alloc"
	NsOpLogZoneRepMigratePrevStop    = "zm/rep-migrate/stop"
	NsOpLogZoneRepMigratePrevDestory = "zm/rep-migrate/destroy"
	NsOpLogZoneRepMigrateNextData    = "zm/rep-migrate/data"
	NsOpLogZoneRepMigrateDone        = "zm/rep-migrate/done"
)

const (
	OpLogNsZoneMasterPodScheduleCharge  = "zm/ps/charge"
	OpLogNsZoneMasterPodScheduleAlloc   = "zm/ps/alloc"
	OpLogNsZoneMasterPodScheduleResFree = "zm/ps/resfree"
)

var (
	OpLogNsZoneMasterPodScheduleRep = func(repId uint32) string {
		if repId > 65535 {
			repId = 65535
		}
		return fmt.Sprintf("zm/ps/rep/%d", repId)
	}
)

type OpLogList []*PbOpLogSets

func (ls *OpLogList) Get(sets_name string) *PbOpLogSets {
	oplogListMu.RLock()
	defer oplogListMu.RUnlock()
	return PbOpLogSetsSliceGet(*ls, sets_name)
}

func (ls *OpLogList) LogSet(sets_name string, version uint32, name, status, msg string) {

	oplogListMu.Lock()
	defer oplogListMu.Unlock()

	sets := PbOpLogSetsSliceGet(*ls, sets_name)
	if sets == nil {
		sets = &PbOpLogSets{
			Name:    sets_name,
			Version: version,
		}
		*ls, _ = PbOpLogSetsSliceSync(*ls, sets)
	}

	if version < sets.Version {
		return
	}

	sets.LogSet(version, name, status, msg)
}

func NewPbOpLogSets(sets_name string, version uint32) *PbOpLogSets {

	return &PbOpLogSets{
		Name:    sets_name,
		Version: version,
	}
}

func (rs *PbOpLogSets) LogSet(version uint32, name, status, message string) {

	oplogSetsMu.Lock()
	defer oplogSetsMu.Unlock()

	if version > 0 && version > rs.Version {
		rs.Version = version
		rs.Items = []*PbOpLogEntry{}
	}

	tn := uint64(time.Now().UnixNano() / 1e6)

	rs.Items, _ = PbOpLogEntrySliceSync(rs.Items, &PbOpLogEntry{
		Name:    name,
		Status:  status,
		Message: message,
		Updated: tn,
	})
}

func (rs *PbOpLogSets) LogSetEntry(entry *PbOpLogEntry) {
	rs.Items, _ = PbOpLogEntrySliceSync(rs.Items, entry)
}

func NewPbOpLogEntry(name, status, message string) *PbOpLogEntry {
	return &PbOpLogEntry{
		Name:    name,
		Status:  status,
		Message: message,
		Updated: uint64(time.Now().UnixNano() / 1e6),
	}
}
