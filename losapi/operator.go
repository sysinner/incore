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
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	op_log_mu sync.RWMutex
)

var (
	OpActionStart   uint32 = 1 << 1
	OpActionStop    uint32 = 1 << 3
	OpActionDestroy uint32 = 1 << 5
	OpActionCharged uint32 = 1 << 7
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
	OpStatusOK    = "ok"
	OpStatusError = "error"
	OpStatusFatal = "fatal"
)

type OpStatus struct {
	User    string           `json:"user,omitempty"`
	Version uint32           `json:"version,omitempty"`
	Items   []*OpStatusEntry `json:"items,omitempty"`
}

type OpStatusEntry struct {
	Name    string            `json:"name,omitempty"`
	Status  types.ArrayString `json:"status"`
	Message string            `json:"message,omitempty"`
	Created types.MetaTime    `json:"created"`
	Updated types.MetaTime    `json:"updated"`
}

func NewOpStatus(user string, version uint32) OpStatus {
	return OpStatus{
		User:    user,
		Version: version,
	}
}

func (rs *OpStatus) Clean() {
	rs.Items = []*OpStatusEntry{}
}

func (rs *OpStatus) Set(name, status, message string) {

	op_log_mu.Lock()
	defer op_log_mu.Unlock()

	for _, v := range rs.Items {
		if name == v.Name {
			v.Updated = types.MetaTimeNow()
			v.Status.Set(status)
			v.Message = message
			return
		}
	}

	rs.Items = append(rs.Items, &OpStatusEntry{
		Name:    name,
		Status:  types.ArrayString([]string{status}),
		Message: message,
		Created: types.MetaTimeNow(),
		Updated: types.MetaTimeNow(),
	})
}

func (rs *OpStatus) Get(name string) *OpStatusEntry {

	op_log_mu.RLock()
	defer op_log_mu.RUnlock()

	for _, v := range rs.Items {
		if name == v.Name {
			return v
		}
	}

	return nil
}

func (rs *OpStatus) Del(name string) {

	op_log_mu.Lock()
	defer op_log_mu.Unlock()

	for i, v := range rs.Items {
		if name == v.Name {
			rs.Items = append(rs.Items[:i], rs.Items[i+1:]...)
			return
		}
	}
}
