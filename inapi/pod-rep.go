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

	"github.com/lessos/lessgo/types"
	"github.com/sysinner/incore/inutils"
)

type PodRep struct {
	Meta types.InnerObjectMeta `json:"meta,omitempty"`

	// Spec defines the behavior of a pod.
	Spec *PodSpecBound `json:"spec,omitempty"`

	// Apps represents the information about a collection of applications to deploy.
	// this is a module for App Engine
	Apps AppInstances `json:"apps,omitempty"`

	// Replica
	Replica PodOperateReplica `json:"replica,omitempty"`

	//
	Operate PodOperate `json:"operate,omitempty"`
}

type PodRepItems []*PodRep

func (it *PodRep) RepKey() string {
	return NsZonePodOpRepKey(it.Meta.ID, it.Replica.RepId)
}

var (
	podRepItemsMu sync.RWMutex
)

func (ls *PodRepItems) Del(repKey string) {
	podRepItemsMu.Lock()
	defer podRepItemsMu.Unlock()
	for i, v := range *ls {
		if v.RepKey() == repKey {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *PodRepItems) Get(podId string) *PodRep {
	podRepItemsMu.RLock()
	defer podRepItemsMu.RUnlock()
	for _, v := range *ls {
		if v.RepKey() == podId {
			return v
		}
	}
	return nil
}

func (ls *PodRepItems) Set(item *PodRep) {
	podRepItemsMu.Lock()
	defer podRepItemsMu.Unlock()

	for i, v := range *ls {
		if v.RepKey() == item.RepKey() {
			(*ls)[i] = item
			return
		}
	}
	*ls = append(*ls, item)
}

func (ls *PodRepItems) Each(fn func(item *PodRep)) {
	podRepItemsMu.RLock()
	defer podRepItemsMu.RUnlock()

	for _, v := range *ls {
		fn(v)
	}
}

func PodRepInstanceName(podId string, repId uint32) string {

	if repId > 65535 {
		repId = 65535
	}

	return fmt.Sprintf(
		"%s-%s",
		podId, inutils.Uint16ToHexString(uint16(repId)),
	)
}
