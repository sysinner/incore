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
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"sort"
	"sync"
)

var (
	resSysMu               sync.RWMutex
	resSysHostMu           sync.RWMutex
	ResSysZoneIdReg        = regexp.MustCompile("^[a-z]{1}[a-z0-9\\-]{1,15}$")
	ResSysCellIdReg        = regexp.MustCompile("^[a-z]{1}[a-z0-9\\-]{1,15}$")
	ResSysHostIdReg        = regexp.MustCompile("^[0-9a-f]{12,16}$")
	ResSysHostSecretKeyReg = regexp.MustCompile("^[0-9a-zA-Z\\+\\/]{20,40}$")
	ResSysNodeNameReg      = regexp.MustCompile("^[0-9a-zA-Z._\\-]{1,30}$")
	res_zone_mu            sync.RWMutex
	resLabelNameReg        = regexp.MustCompile("^[a-z]{1}[a-z0-9-._/]{0,99}$")
	resLabelErrNameEmpty   = errors.New("res_label name cannot be empty")
	resLabelErrNameLength  = errors.New("length of the res_label name must be less than 100")
	resLabelErrNameInvalid = errors.New("invalid res_label name")

	ResSysHostPriorityLength  uint32 = 6
	ResSysHostPriorityMin     uint32 = 1
	ResSysHostPriorityMax     uint32 = ResSysHostPriorityLength - 2
	ResSysHostPriorityDefault uint32 = ResSysHostPriorityLength / 2
	ResNetworkDomainNameRE           = regexp.MustCompile("^[0-9a-z._\\-]{1,100}$")

	ZoneGroupIdRX = regexp.MustCompile("^[a-z]{1}[a-z0-9\\-]{1,7}$")
)

const (
	HostSetupStart   uint32 = 1 << 1  // OpActionStart
	HostSetupStop    uint32 = 1 << 3  // OpActionStop
	HostSetupDestroy uint32 = 1 << 5  // OpActionDestroy
	HostSetupForce   uint32 = 1 << 27 // OpActionForce
)

const (
	ZoneGroupSetupIn  uint64 = 1 << 1
	ZoneGroupSetupOut uint64 = 1 << 2
)

type ZoneDriver interface {
	Name() string
	ConfigSpec() *ConfigSpec
	ConfigValid(cfg *ConfigInstance) error
	HostAlloc(cfg *ConfigInstance, host *ResHost) error
	HostFree(cfg *ConfigInstance, host *ResHost) error
	HostList(cfg *ConfigInstance) ([]*ResHostCloudProvider, error)
}

const (
	ResHostCloudProviderSyncBound  uint64 = 1 << 1
	ResHostCloudProviderSyncCreate uint64 = 1 << 2
	ResHostCloudProviderSyncBind   uint64 = 1 << 3
)

func SysHostActionFilter(op uint32) uint32 {
	if OpActionAllow(op, HostSetupStart) {
		return HostSetupStart
	} else if OpActionAllow(op, HostSetupStop) {
		return HostSetupStop
	} else if OpActionAllow(op, HostSetupDestroy) {
		return HostSetupDestroy
	}
	return HostSetupStart
}

func (obj *ResZone) Cell(id string) *ResCell {

	resSysMu.RLock()
	defer resSysMu.RUnlock()

	for _, v := range obj.Cells {
		if v.Meta.Id == id {
			return v
		}
	}

	return nil
}

func (obj *ResZone) CellSync(item *ResCell) (*ResCell, bool) {

	resSysMu.Lock()
	defer resSysMu.Unlock()

	for i, v := range obj.Cells {
		if v.Meta.Id == item.Meta.Id {
			if v.Meta.Updated < item.Meta.Updated {
				obj.Cells[i] = item
				return item, true
			}
			return v, false
		}
	}

	obj.Cells = append(obj.Cells, item)

	return item, true
}

// Set create or update the res_label entry for "name" to "value".
func (ls *ResZone) OptionSet(name string, value interface{}) error {

	res_zone_mu.Lock()
	defer res_zone_mu.Unlock()

	if len(name) < 1 {
		return resLabelErrNameEmpty
	}

	if len(name) > 100 {
		return resLabelErrNameLength
	}

	if !resLabelNameReg.MatchString(name) {
		return resLabelErrNameInvalid
	}

	svalue := fmt.Sprintf("%v", value)

	for i, prev := range ls.Options {

		if prev.Name == name {

			if prev.Value != svalue {
				ls.Options[i].Value = svalue
			}

			return nil
		}
	}

	ls.Options = append(ls.Options, &Label{
		Name:  name,
		Value: svalue,
	})

	return nil
}

// Get fetch the res_label entry "value" (if any) for "name".
func (ls *ResZone) OptionGet(name string) (string, bool) {

	res_zone_mu.RLock()
	defer res_zone_mu.RUnlock()

	for _, prev := range ls.Options {

		if prev.Name == name {
			return prev.Value, true
		}
	}

	return "", false
}

// Del remove the res_label entry (if any) for "name".
func (ls *ResZone) OptionDel(name string) {

	res_zone_mu.Lock()
	defer res_zone_mu.Unlock()

	for i, prev := range ls.Options {

		if prev.Name == name {
			ls.Options = append(ls.Options[:i], ls.Options[i+1:]...)
			break
		}
	}
}

func (obj *ResZoneMasterList) LeaderAddr() string {

	if v := obj.Item(obj.Leader); v != nil {
		return string(v.Addr)
	}

	return ""
}

func (obj *ResZoneMasterList) Item(id string) *ResZoneMasterNode {

	for _, v := range obj.Items {

		if v.Id == id {
			return v
		}
	}

	return nil
}

func (obj *ResZoneMasterList) Sync(item ResZoneMasterNode) (changed bool) {

	resSysMu.Lock()
	defer resSysMu.Unlock()

	changed = false

	if pv := obj.Item(item.Id); pv != nil {

		if pv.Addr != item.Addr ||
			pv.Action != item.Action {

			pv.Addr = item.Addr
			pv.Action = item.Action

			changed = true
		}

	} else {
		obj.Items = append(obj.Items, &item)
		changed = true
	}

	return changed
}

func (obj *ResZoneMasterList) SyncList(ls *ResZoneMasterList) (changed bool) {

	if (obj.Version >= ls.Version && len(obj.Items) > 0) || len(ls.Items) < 1 {
		return false
	}

	changed = false

	resSysMu.Lock()
	defer resSysMu.Unlock()

	if len(ls.Leader) > 8 && obj.Leader != ls.Leader {
		obj.Leader = ls.Leader
		changed = true
	}

	for i, pv := range obj.Items {

		if nv := ls.Item(pv.Id); nv == nil {
			obj.Items[i].Action = 0
			changed = true
		}
	}

	for _, nv := range ls.Items {

		if pv := obj.Item(nv.Id); pv == nil {
			obj.Items = append(obj.Items, nv)
		} else {

			if pv.Addr != nv.Addr ||
				pv.Action != nv.Action {

				pv.Addr = nv.Addr
				pv.Action = nv.Action

				changed = true
			}
		}
	}

	return changed
}

// ResHostList
func (ls *ResHostList) Item(id string) *ResHost {

	for _, v := range ls.Items {

		if v.Meta.Id == id {
			return v
		}
	}

	return nil
}

func (ls *ResHostList) Del(id string) {
	for i, v := range ls.Items {
		if v.Meta.Id == id {
			ls.Items = append(ls.Items[:i], ls.Items[i+1:]...)
			return
		}
	}
}

func (ls *ResHostList) Sync(item ResHost) (changed bool) {

	if item.Meta == nil {
		return false
	}

	resSysMu.Lock()
	defer resSysMu.Unlock()

	if pv := ls.Item(item.Meta.Id); pv != nil {
		changed = pv.Sync(item)
	} else {
		ls.Items = append(ls.Items, &item)
		changed = true
	}

	return
}

func (obj *ResHost) Sync(item ResHost) (changed bool) {

	if item.Meta != nil {

		if obj.Meta == nil {
			obj.Meta = item.Meta
		}
	}

	if item.Operate != nil {

		if obj.Operate == nil {
			obj.Operate = item.Operate
		} else {

			if obj.Operate.Action != item.Operate.Action ||
				obj.Operate.CellId != item.Operate.CellId {

				obj.Operate.Action = item.Operate.Action
				obj.Operate.CellId = item.Operate.CellId

				changed = true
			}
		}
	}

	if changed = diffchanged(obj.Spec, item.Spec); changed {
		obj.Spec = item.Spec
	}

	if changed = diffchanged(obj.Status, item.Status); changed {
		obj.Status = item.Status
	}

	if changed = diffchanged(obj.CloudProvider, item.CloudProvider); changed {
		obj.CloudProvider = item.CloudProvider
	}

	return
}

func (obj *ResHost) SyncOpCpu(cpu int32) {

	if obj.Operate == nil {
		obj.Operate = &ResHostOperate{}
	}

	obj.Operate.CpuUsed += cpu
}

func (obj *ResHost) SyncOpMem(ram int32) {

	if obj.Operate == nil {
		obj.Operate = &ResHostOperate{}
	}

	obj.Operate.MemUsed += int64(ram)
}

const (
	res_host_port_offset uint32 = 15000
	res_host_port_cutset uint32 = 19999
	res_host_port_limit  int    = 5000
)

func (obj *ResHost) OpPortHas(port uint16) bool {

	resSysHostMu.RLock()
	defer resSysHostMu.RUnlock()

	if obj.Operate == nil {
		return false
	}

	return array_uint32_has(obj.Operate.PortUsed, uint32(port))
}

func (obj *ResHost) OpPortAlloc(port uint16) uint16 {

	resSysHostMu.Lock()
	defer resSysHostMu.Unlock()

	if obj.Operate == nil {
		obj.Operate = &ResHostOperate{}
	}

	if port > 0 {

		if array_uint32_has(obj.Operate.PortUsed, uint32(port)) {
			return 0
		}

		obj.Operate.PortUsed = append(obj.Operate.PortUsed, uint32(port))
		return port
	}

	if len(obj.Operate.PortUsed) > res_host_port_limit {
		return 0
	}

	// random
	rn := res_host_port_cutset - res_host_port_offset
	for i := 0; i < 10; i++ {
		p := res_host_port_offset + (rand.Uint32() % rn)
		if !array_uint32_has(obj.Operate.PortUsed, p) {
			obj.Operate.PortUsed = append(obj.Operate.PortUsed, p)
			return uint16(p)
		}
	}

	//
	offset := res_host_port_offset
	if n := len(obj.Operate.PortUsed); n > 0 {

		offset = obj.Operate.PortUsed[len(obj.Operate.PortUsed)-1] + 1
		if port == 0 && offset < res_host_port_offset {
			offset = res_host_port_offset
		}
	}

	for p := offset; p <= res_host_port_cutset; p++ { // TODO

		if !array_uint32_has(obj.Operate.PortUsed, p) {
			port = uint16(p)
			break
		}
	}

	for p := res_host_port_offset; p < offset; p++ { // TODO

		if !array_uint32_has(obj.Operate.PortUsed, p) {
			port = uint16(p)
			break
		}
	}

	if port > 0 {
		obj.Operate.PortUsed = append(obj.Operate.PortUsed, uint32(port))
	}

	return port
}

func array_uint32_has(ls []uint32, has uint32) bool {

	for _, v := range ls {
		if has == v {
			return true
		}
	}

	return false
}

func (obj *ResHost) OpPortFree(port uint16) {

	resSysHostMu.Lock()
	defer resSysHostMu.Unlock()

	if obj.Operate == nil {
		return
	}

	for i, v := range obj.Operate.PortUsed {

		if v == uint32(port) {
			obj.Operate.PortUsed = append(obj.Operate.PortUsed[:i], obj.Operate.PortUsed[i+1:]...)
			break
		}
	}
}

func (obj *ResHost) OpPortFreeAll() {

	resSysHostMu.Lock()
	defer resSysHostMu.Unlock()

	if obj.Operate == nil {
		return
	}

	obj.Operate.PortUsed = []uint32{}
}

func (obj *ResHost) OpPortSort() {

	if len(obj.Operate.PortUsed) == 0 {
		return
	}

	resSysHostMu.Lock()
	defer resSysHostMu.Unlock()

	sort.Slice(obj.Operate.PortUsed, func(i, j int) bool {
		return obj.Operate.PortUsed[i] < obj.Operate.PortUsed[j]
	})
}

func (obj *ResHost) SyncStatus(item ResHost) (changed bool) {

	if diffchanged(obj.Spec, item.Spec) {
		obj.Spec = item.Spec
		changed = true
	}

	if diffchanged(obj.Status, item.Status) {
		obj.Status = item.Status
		changed = true
	}

	if changed = diffchanged(obj.CloudProvider, item.CloudProvider); changed {
		obj.CloudProvider = item.CloudProvider
	}

	return
}

func diffchanged(dst, src interface{}) bool {

	if src == nil {
		return false
	}

	if dst == nil {
		return true
	}

	return reflect.DeepEqual(dst, src) == false
}
