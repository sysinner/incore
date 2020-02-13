// Copyright 2018 Eryx <evorui аt gmail dοt com>, All rights reserved.
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
	"sort"
	"sync"
	"time"

	"github.com/lessos/lessgo/types"
)

type PodExecutorStatus struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          ExecutorStatuses `json:"items" toml:"items"`
}

// Pod Status
type PodRepStatuses []*PbPodRepStatus

func (ls *PodRepStatuses) Sort() {
	sort.Slice(*ls, func(i, j int) bool {
		return (*ls)[i].RepId < (*ls)[j].RepId
	})
}

// PodStatus represents information about the status of a pod. Status may trail the actual
// state of a system.
type PodStatus struct {
	types.TypeMeta     `json:",inline" toml:",inline"`
	PodId              string          `json:"pod_id,omitempty" toml:"pod_id,omitempty"`
	Action             uint32          `json:"action,omitempty" toml:"action,omitempty"`
	ActionRunning      int             `json:"action_running" toml:"action_running"`
	Replicas           PodRepStatuses  `json:"replicas,omitempty" toml:"replicas,omitempty"`
	Updated            uint32          `json:"updated,omitempty" toml:"updated,omitempty"`
	OpLog              []*PbOpLogEntry `json:"op_log,omitempty" toml:"op_log,omitempty"`
	PaymentCycleAmount float32         `json:"payment_cycle_amount,omitempty" toml:"payment_cycle_amount,omitempty"`
}

func (it *PodStatus) RepSync(v *PbPodRepStatus) bool {
	ls, chg := PbPodRepStatusSliceSync(it.Replicas, v)
	if chg {
		it.Replicas = ls
		it.Replicas.Sort()
	}
	return chg
}

func (it *PodStatus) RepGet(repId uint32) *PbPodRepStatus {
	return PbPodRepStatusSliceGet(it.Replicas, it.PodId, repId)
}

func (it *PodStatus) RepDel(repId uint32) {
	for i, v := range it.Replicas {
		if v.RepId == repId {
			it.Replicas = append(it.Replicas[:i], it.Replicas[i+1:]...)
			return
		}
	}
}

func (it *PodStatus) RepActionAllow(repCap int, op uint32) bool {

	if repCap == len(it.Replicas) {

		allowN := 0
		for _, v := range it.Replicas {
			if int(v.RepId) >= repCap {
				continue
			}
			if OpActionAllow(v.Action, op) {
				allowN += 1
			}
		}

		if allowN == repCap {
			return true
		}
	}

	return false
}

func (it *PodStatus) HealthFails(delaySeconds int32, stateless bool, repCap int32) types.ArrayUint32 {

	if delaySeconds < HealthFailoverActiveTimeMin {
		delaySeconds = HealthFailoverActiveTimeMin
	}

	var (
		repFails = types.ArrayUint32{}
		tn       = uint32(time.Now().Unix())
		failTime = tn - uint32(delaySeconds)
	)

	for _, v := range it.Replicas {

		if v.RepId >= uint32(repCap) {
			continue
		}

		if stateless {

			if v.Updated < failTime {
				repFails.Set(v.RepId)
			}

		} else if v.Health != nil &&
			v.Health.Updated > 0 &&
			v.Health.Updated < failTime {
			repFails.Set(v.RepId)
		}
	}

	return repFails
}

type PodStatusList struct {
	mu    sync.RWMutex
	Items []*PodStatus `json:"items" toml:"items"`
}

func (ls *PodStatusList) Get(id string) *PodStatus {

	ls.mu.RLock()
	defer ls.mu.RUnlock()

	for _, v := range ls.Items {
		if id == v.PodId {
			return v
		}
	}

	return nil
}

func (ls *PodStatusList) Set(v2 *PodStatus) *PodStatus {

	ls.mu.Lock()
	defer ls.mu.Unlock()

	for i, v := range ls.Items {
		if v2.PodId == v.PodId {
			ls.Items[i] = v2
			return v2
		}
	}

	ls.Items = append(ls.Items, v2)
	return v2
}
