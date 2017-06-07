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
	"regexp"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	app_op_mu             sync.RWMutex
	app_op_ref_mu         sync.RWMutex
	app_spec_cfg_name_re2 = regexp.MustCompile("^[a-z]{1}[a-z0-9_]{1,30}$")
)

type AppPhase string

const (
	AppPending   AppPhase = "Pending"
	AppRunning   AppPhase = "Running"
	AppSucceeded AppPhase = "Succeeded"
	AppFailed    AppPhase = "Failed"
)

type AppInstance struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	// Spec defines the behavior of a app.
	Spec AppSpec `json:"spec,omitempty"`

	//
	Operate AppOperate `json:"operate,omitempty"`

	// Status represents the current information about a app. This data may not be up
	// to date.
	Status *AppStatus `json:"status,omitempty"`
}

type AppInstanceList struct {
	types.TypeMeta `json:",inline"`
	Items          AppInstances `json:"items,omitempty"`
}

type AppInstances []AppInstance

func (ls *AppInstances) Sync(app AppInstance) {

	for i, v := range *ls {

		if v.Meta.ID == app.Meta.ID {
			(*ls)[i] = app
			return
		}
	}

	*ls = append(*ls, app)
}

func (ls *AppInstances) ExecutorSync(executor Executor, app_id string) {

	for i, v := range *ls {

		if v.Meta.ID == app_id {
			(*ls)[i].Spec.Executors.Sync(executor)
			break
		}
	}
}

//
type AppSpec struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta"`
	Roles          types.ArrayUint32     `json:"roles,omitempty"`
	Vendor         string                `json:"vendor,omitempty"`
	Description    string                `json:"description,omitempty"`
	Packages       AppPackages           `json:"packages,omitempty"`
	Executors      Executors             `json:"executors,omitempty"`
	VolumeMounts   AppVolumeMounts       `json:"volume_mounts,omitempty"`
	ServicePorts   ServicePorts          `json:"service_ports,omitempty"`
	Configurator   *AppConfigurator      `json:"configurator,omitempty"`
}

type AppSpecList struct {
	types.TypeMeta `json:",inline"`
	Items          []AppSpec `json:"items,omitempty"`
}

type AppPackages []VolumePackage

func (ls *AppPackages) Insert(vol VolumePackage) {

	for i, v := range *ls {

		if v.Name == vol.Name {
			(*ls)[i] = vol
			return
		}
	}

	*ls = append(*ls, vol)
}

func (ls *AppPackages) Remove(name string) {

	for i, v := range *ls {

		if v.Name == name {
			*ls = append((*ls)[0:i], (*ls)[i+1:]...)
			break
		}
	}
}

//
type AppVolumeMount struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BoxBound string `json:"box_bound,omitempty"`
}

type AppVolumeMounts []AppVolumeMount

//
type AppConfigurator struct {
	Name   types.NameIdentifier `json:"name"`
	Fields AppConfigFields      `json:"fields,omitempty"`
}

const (
	AppConfigFieldTypeString     uint16 = 1
	AppConfigFieldTypeSelect     uint16 = 2
	AppConfigFieldTypeAppOpBound uint16 = 10

	AppConfigFieldAutoFillDefaultValue = "defval"
	AppConfigFieldAutoFillHexString_32 = "hexstr_32"
	AppConfigFieldAutoFillBase64_48    = "base64_48"
)

func AppConfigFieldAutoFillValid(v string) bool {

	switch v {

	case AppConfigFieldAutoFillDefaultValue,
		AppConfigFieldAutoFillHexString_32,
		AppConfigFieldAutoFillBase64_48:

	default:
		return false
	}

	return true
}

type AppConfigField struct {
	Name      string        `json:"name"`
	Title     string        `json:"title,omitempty"`
	Prompt    string        `json:"prompt,omitempty"`
	Type      uint16        `json:"type,omitempty"`
	Default   string        `json:"default,omitempty"`
	AutoFill  string        `json:"auto_fill,omitempty"`
	Enums     types.Labels  `json:"enums,omitempty"`
	Validates types.KvPairs `json:"validates,omitempty"`
}

type AppConfigFields []*AppConfigField

func (ls *AppConfigFields) Sync(item AppConfigField) {

	app_op_mu.Lock()
	defer app_op_mu.Unlock()

	if !app_spec_cfg_name_re2.MatchString(item.Name) {
		return
	}

	for i, v := range *ls {

		if v.Name == item.Name {
			(*ls)[i] = &item
			return
		}
	}

	*ls = append(*ls, &item)
}

var (
	AppOperateStart uint16 = 1 << 1
	AppOperateStop  uint16 = 1 << 3
)

//
type AppOperate struct {
	Action        uint16            `json:"action,omitempty"`
	PodId         string            `json:"pod_id,omitempty"`
	Options       AppOptions        `json:"options,omitempty"`
	ResBoundRoles types.ArrayUint32 `json:"res_bound_roles,omitempty"`
}

type AppOption struct {
	Name    types.NameIdentifier `json:"name"`
	Items   types.Labels         `json:"items,omitempty"`
	Subs    types.ArrayString    `json:"subs,omitempty"`
	Ref     *AppOptionRef        `json:"ref,omitempty"`
	User    string               `json:"user,omitempty"`
	Updated uint64               `json:"updated,omitempty"`
}

type AppOptions []*AppOption

func (ls *AppOptions) Get(name string) *AppOption {

	app_op_mu.RLock()
	defer app_op_mu.RUnlock()

	for _, v := range *ls {

		if v.Name == types.NameIdentifier(name) {
			return v
		}
	}

	return nil
}

func (ls *AppOptions) Set(item AppOption) (changed bool) {

	app_op_mu.Lock()
	defer app_op_mu.Unlock()

	for i, v := range *ls {

		if v.Name == item.Name {

			if v.User != item.User {
				return false // TODO
			}

			if item.Updated > v.Updated {
				(*ls)[i] = &item
				return true
			}

			return false
		}
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptions) Sync(item AppOption) (changed bool) {

	app_op_mu.Lock()
	defer app_op_mu.Unlock()

	for _, prev := range *ls {

		if prev.Name != item.Name {
			continue
		}

		if prev.Updated != item.Updated {
			prev.Updated = item.Updated
			changed = true
		}

		if !prev.Items.Equal(item.Items) {
			prev.Items = item.Items
			changed = true
		}

		if !prev.Subs.Equal(item.Subs) {
			prev.Subs = item.Subs
			changed = true
		}

		if (prev.Ref == nil && item.Ref != nil) ||
			(prev.Ref != nil && !prev.Ref.Equal(item.Ref)) {
			prev.Ref = item.Ref
			changed = true
		}

		return changed
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptions) Del(name string) {

	app_op_mu.Lock()
	defer app_op_mu.Unlock()

	for i, prev := range *ls {

		if prev.Name == types.NameIdentifier(name) {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

type AppOptionRef struct {
	AppId string       `json:"app_id"`
	PodId string       `json:"pod_id"`
	Ports ServicePorts `json:"ports,omitempty"`
}

func (it *AppOptionRef) Equal(item *AppOptionRef) bool {

	if it == nil && item != nil {
		return false
	}

	if it != nil {

		if item == nil {
			return true
		}

		if it.AppId != item.AppId ||
			it.PodId != item.PodId ||
			!it.Ports.Equal(item.Ports) {
			return false
		}
	}

	return true
}

type AppOptionRefs []*AppOptionRef

func (ls *AppOptionRefs) Get(app_id string) *AppOptionRef {

	app_op_ref_mu.RLock()
	defer app_op_ref_mu.RUnlock()

	for _, v := range *ls {

		if v.AppId == app_id {
			return v
		}
	}

	return nil
}

func (ls *AppOptionRefs) Sync(item AppOptionRef) (changed bool) {

	app_op_ref_mu.Lock()
	defer app_op_ref_mu.Unlock()

	for _, prev := range *ls {

		if prev.AppId != item.AppId {
			continue
		}

		if prev.PodId != item.PodId {
			prev.PodId = item.PodId
			changed = true
		}

		if !prev.Ports.Equal(item.Ports) {
			prev.Ports = item.Ports
			changed = true
		}

		return changed
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptionRefs) Del(app_id string) {

	app_op_ref_mu.Lock()
	defer app_op_ref_mu.Unlock()

	for i, prev := range *ls {

		if prev.AppId == app_id {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *AppOptionRefs) Equal(items AppOptionRefs) bool {

	app_op_ref_mu.Lock()
	defer app_op_ref_mu.Unlock()

	if len(*ls) != len(items) {
		return false
	}

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.AppId != v2.AppId {
				continue
			}

			if v.PodId != v2.PodId {
				return false
			}

			if !v.Ports.Equal(v2.Ports) {
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

type AppStatus struct {
	Phase AppPhase `json:"phase,omitempty"`
}
