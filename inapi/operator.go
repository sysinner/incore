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
	"strings"
	"sync"
	"time"
)

var (
	op_log_mu      sync.RWMutex
	op_log_list_mu sync.RWMutex
)

var (
	OpActionStart   uint32 = 1 << 1
	OpActionStop    uint32 = 1 << 3
	OpActionDestroy uint32 = 1 << 5
)

func OpActionValid(op uint32) bool {
	return OpActionAllow(
		OpActionStart|OpActionStop|OpActionDestroy,
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

type PbOpLogSetsList []*PbOpLogSets

func (ls *PbOpLogSetsList) Get(sets_name string) *PbOpLogSets {

	op_log_list_mu.Lock()
	defer op_log_list_mu.Unlock()

	for _, v := range *ls {

		if v.Name == sets_name {
			return v
		}
	}

	return nil
}

func (ls *PbOpLogSetsList) Set(sets_name, user string, version uint32) *PbOpLogSets {

	op_log_list_mu.Lock()
	defer op_log_list_mu.Unlock()

	for _, v := range *ls {

		if v.Name == sets_name {
			v.User = user
			v.Version = version
			return v
		}
	}

	sets := NewPbOpLogSets(sets_name, user, version)
	*ls = append(*ls, sets)
	return sets
}

func (ls *PbOpLogSetsList) LogSet(sets_name, name, status, message string) {

	op_log_list_mu.Lock()
	defer op_log_list_mu.Unlock()

	for _, v := range *ls {

		if v.Name == sets_name {
			v.Set(name, status, message)
			break
		}
	}
}

func NewPbOpLogSets(sets_name, user string, version uint32) *PbOpLogSets {
	return &PbOpLogSets{
		Name:    sets_name,
		User:    user,
		Version: version,
	}
}

func (rs *PbOpLogSets) Clean() {
	rs.Items = []*PbOpLogEntry{}
}

func (rs *PbOpLogSets) Set(name, status, message string) {

	op_log_mu.Lock()
	defer op_log_mu.Unlock()

	name = strings.ToLower(name)
	status = strings.ToLower(status)

	tn := uint32(time.Now().Unix())

	for _, v := range rs.Items {
		if name == v.Name {
			v.Updated = tn
			v.Message = message
			for _, v2 := range v.Status {
				if v2 == status {
					return
				}
			}
			v.Status = []string{status}
			return
		}
	}

	rs.Items = append(rs.Items, &PbOpLogEntry{
		Name:    name,
		Status:  []string{status},
		Message: message,
		Created: tn,
		Updated: tn,
	})
}

func (rs *PbOpLogSets) Get(name string) *PbOpLogEntry {

	op_log_mu.RLock()
	defer op_log_mu.RUnlock()

	for _, v := range rs.Items {
		if name == v.Name {
			return v
		}
	}

	return nil
}

func (rs *PbOpLogSets) Del(name string) {

	op_log_mu.Lock()
	defer op_log_mu.Unlock()

	for i, v := range rs.Items {
		if name == v.Name {
			rs.Items = append(rs.Items[:i], rs.Items[i+1:]...)
			return
		}
	}
}
