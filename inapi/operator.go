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
	OpActionWarn      uint32 = 1 << 11
	oplog_list_mu     sync.RWMutex
	oplog_sets_mu     sync.RWMutex
)

func OpActionValid(op uint32) bool {
	return OpActionAllow(
		OpActionStart|OpActionRunning|
			OpActionStop|OpActionStopped|
			OpActionDestroy|OpActionDestroyed|
			OpActionWarn,
		op,
	)
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

//
const (
	PbOpLogOK    = "ok"
	PbOpLogInfo  = "info"
	PbOpLogWarn  = "warn"
	PbOpLogError = "error"
	PbOpLogFatal = "fatal"
)

type OpLogList []*PbOpLogSets

func (ls *OpLogList) Get(sets_name string) *PbOpLogSets {
	oplog_list_mu.RLock()
	defer oplog_list_mu.RUnlock()
	return PbOpLogSetsSliceGet(*ls, sets_name)
}

func (ls *OpLogList) LogSet(sets_name string, version uint32, name, status, msg string) {

	oplog_list_mu.Lock()
	defer oplog_list_mu.Unlock()

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

	oplog_sets_mu.Lock()
	defer oplog_sets_mu.Unlock()

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
