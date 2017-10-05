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

package inapi

import (
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	res_bound_mu sync.RWMutex
	res_mu       sync.RWMutex
)

const (
	ResourceTypeDomain = "domain"
	ResourceActionOK   = "ok"
)

type Resource struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`
	Description    string                `json:"description,omitempty"`
	Operate        ResOperate            `json:"operate,omitempty"`
	Bounds         ResourceBounds        `json:"bounds,omitempty"`
	Options        types.Labels          `json:"options,omitempty"`
	Action         types.StringArray     `json:"action,omitempty"`
	Updated        uint64                `json:"updated,omitempty"`
}

type ResourceList struct {
	types.TypeMeta `json:",inline"`
	Items          []Resource `json:"items,omitempty"`
}

type ResOperate struct {
	AppId string `json:"app_id,omitempty"`
}

type ResourceBound struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Action uint8  `json:"action,omitempty"`
}

type ResourceBounds []*ResourceBound

func (ls *ResourceBounds) Sync(item ResourceBound) (changed bool, err error) {

	name := types.NewNameIdentifier(item.Name)
	if err = name.Valid(); err != nil {
		return false, err
	}
	item.Name = name.String()

	res_bound_mu.Lock()
	defer res_bound_mu.Unlock()

	for i, prev := range *ls {

		if prev.Name == item.Name {

			if prev.Value != item.Value {
				(*ls)[i].Value = item.Value
				changed = true
			}

			if prev.Action != item.Action {
				(*ls)[i].Action = item.Action
				changed = true
			}

			return changed, nil
		}
	}

	*ls = append(*ls, &item)

	return true, nil
}

func (ls ResourceBounds) Get(name string) *ResourceBound {

	res_bound_mu.RLock()
	defer res_bound_mu.RUnlock()

	name = types.NewNameIdentifier(name).String()

	for _, prev := range ls {

		if prev.Name == name {
			return prev
		}
	}

	return nil
}

func (ls *ResourceBounds) Del(name string) {

	res_bound_mu.Lock()
	defer res_bound_mu.Unlock()

	name = types.NewNameIdentifier(name).String()

	for i, prev := range *ls {

		if prev.Name == name {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			break
		}
	}
}

func (ls *ResourceBounds) Equal(items ResourceBounds) bool {

	res_bound_mu.RLock()
	defer res_bound_mu.RUnlock()

	if len(*ls) != len(items) {
		return false
	}

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.Name != v2.Name {
				continue
			}

			if v.Value != v2.Value ||
				v.Action != v2.Action {
				return false
			}

			hit = true
			break
		}

		if !hit {
			return false
		}
	}

	return true
}
