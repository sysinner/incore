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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	podOpMu             sync.RWMutex
	podItemsMu          sync.RWMutex
	pod_st_mu           sync.RWMutex
	PodIdReg            = regexp.MustCompile("^[a-f0-9]{16,24}$")
	PodSpecPlanIdReg    = regexp.MustCompile("^[a-z]{1}[a-z0-9]{1,9}$")
	PodSpecImageNameReg = regexp.MustCompile("^[a-z][a-z0-9-_/]{1,50}$")
	PodSpecImageTagReg  = regexp.MustCompile("^[a-z0-9.-_]{1,30}$")
	PodDestroyTTL       = int64(86400)
	PodPlanChargeCycle  = uint64(3600)
)

const (
	PodSpecBoxImageDocker = "docker"
	PodSpecBoxImageRkt    = "rkt"
	PodSpecBoxImagePouch  = "pouch"
)

const (
	PodSpecBoxImageActionEnable  uint32 = 1 << 1
	PodSpecBoxImageActionDisable uint32 = 1 << 3
)

var (
	SpecOsDistRE  = regexp.MustCompile(`el7|el8|all`)
	SpecCpuArchRE = regexp.MustCompile(`x64|src`)
)

const (
	SpecCpuArchAmd64 = "x64"
)

const (
	SpecStatusActive  = "active"
	SpecStatusSuspend = "suspend"
)

const (
	OpStatusPending   = "pending"
	OpStatusRunning   = "running"
	OpStatusStopped   = "stopped"
	OpStatusFailed    = "failed"
	OpStatusDestroyed = "destroyed"
	OpStatusUnknown   = "unknown"
)

func PodSpecBoxImageDriverName(v PbPodSpecBoxImageDriver) string {

	switch v {
	case PbPodSpecBoxImageDriver_Docker:
		return PodSpecBoxImageDocker

	case PbPodSpecBoxImageDriver_Pouch:
		return PodSpecBoxImagePouch
	}

	return ""
}

func PodSpecBoxImageDriver(name string) PbPodSpecBoxImageDriver {
	switch name {
	case PodSpecBoxImageDocker:
		return PbPodSpecBoxImageDriver_Docker

	case PodSpecBoxImagePouch:
		return PbPodSpecBoxImageDriver_Pouch
	}
	return PbPodSpecBoxImageDriver_Unknown
}

// Pod is a collection of containers, used as either input (create, update) or as output (list, get).
type Pod struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	// Spec defines the behavior of a pod.
	Spec *PodSpecBound `json:"spec,omitempty" toml:"spec,omitempty"`

	// Apps represents the information about a collection of applications to deploy.
	// this is a module for App Engine
	Apps AppInstances `json:"apps,omitempty" toml:"apps,omitempty"`

	//
	Operate PodOperate `json:"operate,omitempty" toml:"operate,omitempty"`

	// Status represents the current information about a pod. This data may not be up
	// to date.
	Status *PodStatus `json:"status,omitempty" toml:"status,omitempty"`

	//
	Payment *PodPayment `json:"payment,omitempty" toml:"payment,omitempty"`
}

type PodEstimateList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []*PodEstimateEntry `json:"items" toml:"items"`
}

type PodEstimateEntry struct {
	Name        string  `json:"name" toml:"name"`
	CycleAmount float64 `json:"cycle_amount" toml:"cycle_amount"`
	CycleTime   uint64  `json:"cycle_time" toml:"cycle_time"`
}

func (pod *Pod) AppServicePorts() ServicePorts {

	var ports ServicePorts

	for _, va := range pod.Apps {

		if OpActionAllow(va.Operate.Action, OpActionDestroy) {
			continue
		}

		for _, sp := range va.Spec.ServicePorts {
			ports.Sync(*sp)
		}
	}

	if pod.Operate.Access != nil && pod.Operate.Access.SshOn {
		ports.Sync(ServicePort{
			Name:    "ssh",
			BoxPort: 2022,
		})
	}

	return ports
}

func (pod *Pod) OpRepCapValid(num_new int32) error {

	if num_new < AppSpecExpDeployRepNumMin {
		return errors.New(fmt.Sprintf("RepNum %d conflict with Min Limit %d",
			num_new, AppSpecExpDeployRepNumMin))
	}
	if num_new > AppSpecExpDeployRepNumMax {
		return errors.New(fmt.Sprintf("RepNum %d conflict with Max Limit %d",
			num_new, AppSpecExpDeployRepNumMax))
	}

	if num_new != pod.Operate.ReplicaCap && pod.Apps != nil {

		for _, v := range pod.Apps {
			if v.Spec.ExpDeploy == nil {
				v.Spec.ExpDeploy = &AppSpecExpDeployRequirements{}
			}
			if num_new < v.Spec.ExpDeploy.RepMin {
				return errors.New(fmt.Sprintf("RepNum %d conflict with AppSpec %s Min Limit %d",
					num_new, v.Spec.Meta.Name, v.Spec.ExpDeploy.RepMin))
			}
			if num_new > v.Spec.ExpDeploy.RepMax {
				return errors.New(fmt.Sprintf("RepNum %d conflict with AppSpec %s Max Limit %d",
					num_new, v.Spec.Meta.Name, v.Spec.ExpDeploy.RepMax))
			}
		}
	}

	return nil
}

func (pod *Pod) OpSysStateValid(state_new int32) error {

	if state_new != pod.Operate.ExpSysState {
		if pod.Apps != nil &&
			!pod.Apps.SpecExpDeployStateless() &&
			state_new == AppSpecExpDeploySysStateless {
			return errors.New("State conflict with AppSpec")
		}
	}

	return nil
}

func (it *Pod) OpSysStateless() bool {
	if it.Operate.ExpSysState == AppSpecExpDeploySysStateless {
		return true
	}
	return false
}

func (pod *Pod) OpResScheduleFit() bool {

	if pod.Spec == nil {
		return false
	}

	var (
		cpu int32 = 0
		mem int32 = 0
		vol int32 = 0
	)

	if OpActionAllow(pod.Operate.Action, OpActionStart) {

		if pod.Spec.VolSys == nil {
			return false
		}

		//
		destRes := pod.Spec.ResComputeBound()
		cpu, mem = destRes.CpuLimit, destRes.MemLimit
	}

	destNum := int32(0)

	for _, v := range pod.Operate.Replicas {

		if v.ResCpu == cpu &&
			v.ResMem == mem &&
			v.VolSys == vol &&
			OpActionAllow(pod.Operate.Action, v.Action) {
			destNum += 1
		}
	}

	return destNum == pod.Operate.ReplicaCap
}

func (pod *Pod) PodRepClone(repId uint32) *PodRep {

	return &PodRep{
		Meta:    pod.Meta,
		Spec:    pod.Spec,
		Apps:    pod.Apps,
		Operate: pod.Operate,
		Replica: PodOperateReplica{
			RepId:  repId,
			Action: pod.Operate.Action,
		},
	}
}

func (it *Pod) Stateless() bool {
	if it.OpSysStateless() &&
		it.Apps.SpecExpDeployStateless() {
		return true
	}
	return false
}

func (pod *Pod) FailoverEnable() bool {

	if pod.Apps.SpecExpDeployFailoverEnable() {
		return true
	}

	if pod.Stateless() {
		return true
	}

	return false
}

type PodItems []*Pod

func (ls *PodItems) Get(podId string) *Pod {
	podItemsMu.RLock()
	defer podItemsMu.RUnlock()
	for _, v := range *ls {
		if v.Meta.ID == podId {
			return v
		}
	}
	return nil
}

func (ls *PodItems) Set(item *Pod) {
	podItemsMu.Lock()
	defer podItemsMu.Unlock()

	for i, v := range *ls {
		if v.Meta.ID == item.Meta.ID {
			(*ls)[i] = item
			return
		}
	}
	*ls = append(*ls, item)
}

func (ls *PodItems) Del(podId string) {
	podItemsMu.Lock()
	defer podItemsMu.Unlock()
	for i, v := range *ls {
		if v.Meta.ID == podId {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *PodItems) Each(fn func(item *Pod)) {
	podItemsMu.RLock()
	defer podItemsMu.RUnlock()

	for _, v := range *ls {
		fn(v)
	}
}

// PodList is a list of Pods.
type PodList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          PodItems           `json:"items" toml:"items"`
	UserTransfers  []*PodUserTransfer `json:"user_transfers,omitempty" toml:"user_transfers,omitempty"`
}

// PodSpecBound is a description of a bound spec based on PodSpecPlan
type PodSpecBound struct {
	Ref       ObjectReference         `json:"ref,omitempty" toml:"ref,omitempty"`
	Zone      string                  `json:"zone,omitempty" toml:"zone,omitempty"`
	Cell      string                  `json:"cell,omitempty" toml:"cell,omitempty"`
	BoxDriver string                  `json:"box_driver,omitempty" toml:"box_driver,omitempty"`
	Labels    types.Labels            `json:"labels,omitempty" toml:"labels,omitempty"`
	VolSys    *ResVolBound            `json:"vol_sys,omitempty" toml:"vol_sys,omitempty"`
	Box       PodSpecBoxBound         `json:"box,omitempty" toml:"box,omitempty"`
	Volumes   []PodSpecResVolumeBound `json:"volumes,omitempty" toml:"volumes,omitempty"`
}

type jsonPodSpecBound PodSpecBound

// struct upgrade
func (it *PodSpecBound) UnmarshalJSON(b []byte) error {

	var it2 jsonPodSpecBound
	if err := json.Unmarshal(b, &it2); err != nil {
		return err
	}

	if (it2.VolSys == nil || it2.VolSys.Size == 0) && len(it2.Volumes) > 0 {
		it2.VolSys = &ResVolBound{
			RefId:   it2.Volumes[0].Ref.Id,
			RefName: it2.Volumes[0].Ref.Name,
			Size:    it2.Volumes[0].SizeLimit,
			Attrs:   it2.Volumes[0].Attrs,
		}
	}

	*it = PodSpecBound(it2)

	return nil
}

// struct upgrade
func (it PodSpecBound) MarshalJSON() ([]byte, error) {

	if (it.VolSys == nil || it.VolSys.Size == 0) && len(it.Volumes) > 0 {
		it.VolSys = &ResVolBound{
			RefId:   it.Volumes[0].Ref.Id,
			RefName: it.Volumes[0].Ref.Name,
			Size:    it.Volumes[0].SizeLimit,
			Attrs:   it.Volumes[0].Attrs,
		}
	}

	return json.Marshal(jsonPodSpecBound(it))
}

func (obj *PodSpecBound) ResComputeBound() *PodSpecBoxResComputeBound {

	rs := &PodSpecBoxResComputeBound{}

	if obj != nil {

		if obj.Box.Resources != nil {
			rs.CpuLimit = obj.Box.Resources.CpuLimit
			rs.MemLimit = obj.Box.Resources.MemLimit
		}
	}

	return rs
}

type PodSpecBoundList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PodSpecBound `json:"items,omitempty" toml:"items,omitempty"`
}

// ObjectReference contains enough information to let you inspect or modify the referred object
type ObjectReference struct {
	Id      string `json:"id,omitempty" toml:"id,omitempty"`
	Name    string `json:"name,omitempty" toml:"name,omitempty"`
	Version string `json:"version,omitempty" toml:"version,omitempty"`
	Title   string `json:"title,omitempty" toml:"title,omitempty"`
}

type PodSpecResVolumeBound struct {
	Ref       ObjectReference `json:"ref,omitempty" toml:"ref,omitempty"`
	Name      string          `json:"name" toml:"name"`
	Labels    types.Labels    `json:"labels,omitempty" toml:"labels,omitempty"`
	SizeLimit int32           `json:"size_limit,omitempty" toml:"size_limit,omitempty"` // in GiB
	Attrs     uint32          `json:"attrs,omitempty" toml:"attrs,omitempty"`
}

type PodSpecBoxBound struct {
	Name      string                     `json:"name,omitempty" toml:"name,omitempty"`
	Image     PodSpecBoxImageBound       `json:"image,omitempty" toml:"image,omitempty"`
	Resources *PodSpecBoxResComputeBound `json:"resources,omitempty" toml:"resources,omitempty"`
	Mounts    []*PbVolumeMount           `json:"mounts,omitempty" toml:"mounts,omitempty"`
	Ports     Ports                      `json:"ports,omitempty" toml:"ports,omitempty"`
	Command   []string                   `json:"command,omitempty" toml:"command,omitempty"`
	Updated   types.MetaTime             `json:"updated,omitempty" toml:"updated,omitempty"`
}

type PodSpecBoxImageBound struct {
	Ref *ObjectReference `json:"ref,omitempty" toml:"ref,omitempty"`

	RefName  string `json:"ref_name" toml:"ref_name"`
	RefTag   string `json:"ref_tag" toml:"ref_tag"`
	RefTitle string `json:"ref_title" toml:"ref_title"`

	Driver string `json:"driver,omitempty" toml:"driver,omitempty"`

	// Options types.Labels `json:"options,omitempty" toml:"options,omitempty"`

	// Distribution short name of the operating system.
	//  ex: el6, el7, deb7, ubu1404, ...
	OsDist string `json:"os_dist,omitempty" toml:"os_dist,omitempty"`

	// A human-readable description of the operating system.
	// OsName string `json:"os_name,omitempty" toml:"os_name,omitempty"`

	// Architecture indicates the type of hardware.
	//  ex: amd64, armv6l, ...
	Arch string `json:"arch,omitempty" toml:"arch,omitempty"`
}

type PodSpecBoxResComputeBound struct {
	Ref      *ObjectReference `json:"ref,omitempty" toml:"ref,omitempty"`
	CpuLimit int32            `json:"cpu_limit,omitempty" toml:"cpu_limit,omitempty"` // in .1 Cores
	MemLimit int32            `json:"mem_limit,omitempty" toml:"mem_limit,omitempty"` // in MiB
}

type PodSpecBoxImage struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	Name      string `json:"name" toml:"name"`
	Tag       string `json:"tag" toml:"tag"`
	SortOrder int    `json:"sort_order" toml:"sort_order"`
	Action    uint32 `json:"action,omitempty" toml:"action,omitempty"`

	// Container type of the image.
	//  ex: docker, pouch, ...
	Driver string `json:"driver,omitempty" toml:"driver,omitempty"`

	// Status string `json:"status,omitempty" toml:"status,omitempty"`

	// TODO
	// AccessRoles string `json:"access_roles,omitempty" toml:"access_roles,omitempty"`

	// Options are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "docker/image/name", value: "centos/lastest"},
	//  {name: "example.com/spec/name", value: "hello"}, ...
	// Options types.Labels `json:"options,omitempty" toml:"options,omitempty"`

	// Annotations are name value pairs that representing additional information,
	// any extra metadata you wish may be added to the list.
	// ex:
	//  {name: "homepage", value: "http://example.com"}, ...
	// Annotations types.Labels `json:"annotations,omitempty" toml:"annotations,omitempty"`

	// Type name of the operating system.
	//  ex: linux, freebsd, darwin, ...
	// OsType string `json:"os_type,omitempty" toml:"os_type,omitempty"`

	// Distribution short name of the operating system.
	//  ex: el7, deb9, ubu1804, ...
	OsDist string `json:"os_dist,omitempty" toml:"os_dist,omitempty"`

	// Version of the operating system.
	// OsVersion string `json:"os_version,omitempty" toml:"os_version,omitempty"`

	// A human-readable description of the operating system.
	// OsName string `json:"os_name,omitempty" toml:"os_name,omitempty"`

	// Architecture indicates the type of hardware.
	//  ex: x64, armv6l, ...
	Arch string `json:"arch,omitempty" toml:"arch,omitempty"`
}

type PodSpecBoxImageList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PodSpecBoxImage `json:"items,omitempty" toml:"items,omitempty"`
}

type PodSpecResCompute struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	Status string `json:"status,omitempty" toml:"status,omitempty"`

	// Labels are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "plan/name", value: "general"}, ...
	Labels types.Labels `json:"labels,omitempty" toml:"labels,omitempty"`

	// CPU, in Cores. (1 = .1 Cores)
	CpuLimit int32 `json:"cpu_limit,omitempty" toml:"cpu_limit,omitempty"`

	// Memory, in MiB
	MemLimit int32 `json:"mem_limit,omitempty" toml:"mem_limit,omitempty"`
}

type PodSpecPlanResComputeBounds []*PodSpecPlanResComputeBound

func (s PodSpecPlanResComputeBounds) Len() int {
	return len(s)
}

func (s PodSpecPlanResComputeBounds) Less(i, j int) bool {
	if s[i].CpuLimit < s[j].CpuLimit ||
		(s[i].CpuLimit == s[j].CpuLimit && s[i].MemLimit < s[j].MemLimit) {
		return true
	}
	return false
}

func (s PodSpecPlanResComputeBounds) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type PodSpecResComputes []*PodSpecResCompute

type PodSpecResComputeList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          PodSpecResComputes `json:"items,omitempty" toml:"items,omitempty"`
}

func (s PodSpecResComputes) Len() int {
	return len(s)
}

func (s PodSpecResComputes) Less(i, j int) bool {

	if s[i].CpuLimit < s[j].CpuLimit ||
		(s[i].CpuLimit == s[j].CpuLimit && s[i].MemLimit < s[j].MemLimit) {
		return true
	}

	return false
}

func (s PodSpecResComputes) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type PodSpecResComputeCharge struct {
	Type  uint8   `json:"type" toml:"type"`
	Cycle uint64  `json:"cycle" toml:"cycle"` // default to 3600 seconds
	Cpu   float64 `json:"cpu" toml:"cpu"`     // value in Cores
	Mem   float64 `json:"mem" toml:"mem"`     // value in MiB
}

type PodSpecResVolume struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	Status string `json:"status,omitempty" toml:"status,omitempty"`

	// Labels are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "plan/name", value: "general"}, ...
	Labels types.Labels `json:"labels,omitempty" toml:"labels,omitempty"`

	// Volume size, in GiB.
	Limit   int32  `json:"limit,omitempty" toml:"limit,omitempty"`     // max to 1000 GB
	Request int32  `json:"request,omitempty" toml:"request,omitempty"` // start from 1 GiB
	Step    int32  `json:"step,omitempty" toml:"step,omitempty"`       // every step by 1 GiB
	Default int32  `json:"default,omitempty" toml:"default,omitempty"` // default to 1 GiB
	Attrs   uint32 `json:"attrs,omitempty" toml:"attrs,omitempty"`
}

type PodSpecResVolumeList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PodSpecResVolume `json:"items,omitempty" toml:"items,omitempty"`
}

type PodSpecResVolumeCharge struct {
	Type  uint8   `json:"type" toml:"type"`
	Cycle uint64  `json:"cycle" toml:"cycle"` // default to 3600 seconds
	Value float64 `json:"value" toml:"value"`
}

// TODO
type PodSpecResourceNetwork struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`
}

// TODO
type PodSpecResourceNetworkList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []PodSpecResourceNetwork `json:"items,omitempty" toml:"items,omitempty"`
}

type PodSpecPlanResourceCharge struct {
	Type  uint8  `json:"type" toml:"type"`
	Cycle uint64 `json:"cycle" toml:"cycle"` // default to 3600 seconds
}

type PodSpecPlanBoxImageBound struct {
	RefId     string `json:"ref_id" toml:"ref_id"`
	RefName   string `json:"ref_name" toml:"ref_name"`
	RefTag    string `json:"ref_tag" toml:"ref_tag"`
	RefTitle  string `json:"ref_title" toml:"ref_title"`
	Driver    string `json:"driver,omitempty" toml:"driver,omitempty"`
	OsDist    string `json:"os_dist,omitempty" toml:"os_dist,omitempty"`
	Arch      string `json:"arch,omitempty" toml:"arch,omitempty"`
	SortOrder int    `json:"sort_order" toml:"sort_order"`
	// Options types.Labels `json:"options,omitempty" toml:"options,omitempty"`
}

type PodSpecPlanResComputeBound struct {
	RefId    string `json:"ref_id" toml:"ref_id"`
	CpuLimit int32  `json:"cpu_limit" toml:"cpu_limit"` // in .1 Cores
	MemLimit int32  `json:"mem_limit" toml:"mem_limit"` // in MiB
}

type PodSpecPlanResVolumeBound struct {
	RefId       string       `json:"ref_id" toml:"ref_id"`
	RefName     string       `json:"ref_name" toml:"ref_name"`
	Limit       int32        `json:"limit,omitempty" toml:"limit,omitempty"`     // max to 2000 GB
	Request     int32        `json:"request,omitempty" toml:"request,omitempty"` // start from 1 GiB
	Step        int32        `json:"step,omitempty" toml:"step,omitempty"`       // every step by 1 GiB
	Default     int32        `json:"default,omitempty" toml:"default,omitempty"` // default to 1 GiB
	Labels      types.Labels `json:"labels,omitempty" toml:"labels,omitempty"`
	Attrs       uint32       `json:"attrs,omitempty" toml:"attrs,omitempty"`
	ChargeValue float64      `json:"charge_value,omitempty" toml:"charge_value,omitempty"`
}

type PodSpecPlan struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	Status    string                  `json:"status,omitempty" toml:"status,omitempty"`
	Zones     []*PodSpecPlanZoneBound `json:"zones,omitempty" toml:"zones,omitempty"`
	SortOrder int                     `json:"sort_order" toml:"sort_order"`

	Labels      types.Labels `json:"labels,omitempty" toml:"labels,omitempty"`
	Annotations types.Labels `json:"annotations,omitempty" toml:"annotations,omitempty"`

	Images       []*PodSpecPlanBoxImageBound `json:"images,omitempty" toml:"images,omitempty"`
	ImageDefault string                      `json:"image_default,omitempty" toml:"image_default,omitempty"`

	ResComputes       PodSpecPlanResComputeBounds `json:"res_computes,omitempty" toml:"res_computes,omitempty"`
	ResComputeDefault string                      `json:"res_compute_default,omitempty" toml:"res_compute_default,omitempty"`
	ResComputeCharge  PodSpecResComputeCharge     `json:"res_compute_charge,omitempty" toml:"res_compute_charge,omitempty"`

	ResVolumes       []*PodSpecPlanResVolumeBound `json:"res_volumes,omitempty" toml:"res_volumes,omitempty"`
	ResVolumeDefault string                       `json:"res_volume_default,omitempty" toml:"res_volume_default,omitempty"`
	ResVolumeCharge  PodSpecResVolumeCharge       `json:"res_volume_charge,omitempty" toml:"res_volume_charge,omitempty"`

	ResourceCharge PodSpecPlanResourceCharge `json:"res_charge" toml:"res_charge"`
}

// TODO
func (s *PodSpecPlan) ChargeFix() {
	s.ResourceCharge.Cycle = PodPlanChargeCycle
	s.ResComputeCharge.Cpu = 0.1     // 0.07778
	s.ResComputeCharge.Mem = 0.0001  // 0.00005
	s.ResVolumeCharge.Value = 0.0005 // 0.0004
}

func (s *PodSpecPlan) VolCharge(ref_id string) float64 {

	for _, v := range s.ResVolumes {
		if ref_id == v.RefId {
			if v.ChargeValue > 0 {
				return v.ChargeValue
			}
			break
		}
	}
	return s.ResVolumeCharge.Value
}

func (it *PodSpecPlan) ImagesSort() {
	sort.Slice(it.Images, func(i, j int) bool {
		return it.Images[i].SortOrder < it.Images[j].SortOrder
	})
}

func (s PodSpecPlan) Image(id string) *PodSpecPlanBoxImageBound {

	for _, v := range s.Images {

		if v.RefId == id {
			return v
		}
	}

	return nil
}

func (s PodSpecPlan) ResCompute(id string) *PodSpecPlanResComputeBound {

	for _, v := range s.ResComputes {

		if v.RefId == id {
			return v
		}
	}

	return nil
}

func (s PodSpecPlan) ResVolume(id string) *PodSpecPlanResVolumeBound {

	for _, v := range s.ResVolumes {

		if v.RefId == id {
			return v
		}
	}

	return nil
}

type PodSpecPlans []*PodSpecPlan

type PodSpecPlanList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          PodSpecPlans `json:"items,omitempty" toml:"items,omitempty"`
}

func (ls *PodSpecPlans) Get(plan_id string) *PodSpecPlan {
	for _, v := range *ls {
		if v.Meta.ID == plan_id {
			return v
		}
	}
	return nil
}

func (ls *PodSpecPlanList) Get(plan_id string) *PodSpecPlan {
	return ls.Items.Get(plan_id)
}

type PodSpecPlanZoneBound struct {
	Name  string            `json:"name,omitempty" toml:"name,omitempty"`
	Cells types.ArrayString `json:"cells,omitempty" toml:"cells,omitempty"`
}

type PodCreate struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Owner          string       `json:"owner,omitempty" toml:"owner,omitempty"`
	Pod            string       `json:"pod,omitempty" toml:"pod,omitempty"`
	Name           string       `json:"name" toml:"name"`
	Plan           string       `json:"plan" toml:"plan"`
	Zone           string       `json:"zone" toml:"zone"`
	Cell           string       `json:"cell" toml:"cell"`
	ResVolume      string       `json:"res_volume" toml:"res_volume"`
	ResVolumeSize  int32        `json:"res_volume_size" toml:"res_volume_size"` // in GiB
	Box            PodCreateBox `json:"box" toml:"box"`
}

type PodCreateBox struct {
	Name               string `json:"name" toml:"name"`
	Image              string `json:"image" toml:"image"`
	ResCompute         string `json:"res_compute" toml:"res_compute"`
	ResComputeCpuLimit int32  `json:"res_compute_cpu_limit,omitempty" toml:"res_compute_cpu_limit,omitempty"` // in .1 Cores
	ResComputeMemLimit int32  `json:"res_compute_mem_limit,omitempty" toml:"res_compute_mem_limit,omitempty"` // in MiB
}

func (s *PodCreate) Valid(plan PodSpecPlan) error {

	if s.Name == "" {
		return errors.New("No Name Found")
	}

	hit := false

	for _, zone := range plan.Zones {

		if zone.Name != s.Zone {
			continue
		}

		for _, cell := range zone.Cells {

			if cell == s.Cell {
				hit = true
				break
			}
		}

		break
	}

	if !hit {
		return errors.New("No Zone/Cell Found")
	}
	hit = false

	if s.ResVolumeSize < 1 || s.ResVolumeSize > 2000 {
		return errors.New("Invalid ResVolumeSize")
	}

	for _, vol := range plan.ResVolumes {

		if vol.RefId != s.ResVolume {
			continue
		}

		if s.ResVolumeSize > int32(vol.Limit) ||
			s.ResVolumeSize < vol.Request {
			return errors.New("Invalid ResVolumeSize")
		}

		hit = true
		break
	}

	if !hit {
		return errors.New("No ResVolume Found")
	}

	rv := plan.ResCompute(s.Box.ResCompute)
	if rv == nil {
		return errors.New("ResCompute Not Found")
	}

	s.Box.ResComputeCpuLimit = rv.CpuLimit
	s.Box.ResComputeMemLimit = rv.MemLimit

	if s.Box.ResComputeCpuLimit < 1 {
		return errors.New("Invalid ResCompute Plan")
	}

	return nil
}

type PodOperate struct {
	Action       uint32                   `json:"action,omitempty" toml:"action,omitempty"`
	Version      uint32                   `json:"version,omitempty" toml:"version,omitempty"`
	Priority     int                      `json:"priority,omitempty" toml:"priority,omitempty"` // TODO
	ReplicaCap   int32                    `json:"replica_cap,omitempty" toml:"replica_cap,omitempty"`
	Replicas     PodOperateReplicas       `json:"replicas,omitempty" toml:"replicas,omitempty"`
	OpLog        []*PbOpLogEntry          `json:"op_log,omitempty" toml:"op_log,omitempty"`
	Operated     uint32                   `json:"operated,omitempty" toml:"operated,omitempty"`
	Access       *PodOperateAccess        `json:"access,omitempty" toml:"access,omitempty"`
	BindServices []*AppServicePortPodBind `json:"bind_services,omitempty" toml:"bind_services,omitempty"`
	Failover     *PodOperateFailover      `json:"failover,omitempty" toml:"failover,omitempty"`
	Deploy       *PodOperateDeploy        `json:"deploy,omitempty" toml:"deploy,omitempty"`
	ExpSysState  int32                    `json:"exp_sys_state,omitempty" toml:"exp_sys_state,omitempty"`
	ExpMigrates  []uint32                 `json:"exp_migrates,omitempty" toml:"exp_migrates,omitempty"`
}

var (
	PodOpRepActStart          = OpActionStart
	PodOpRepActStop           = OpActionStop
	PodOpRepActFree           = OpActionDestroy
	PodOpRepActMigrate        = OpActionMigrate
	PodOpRepActWait    uint32 = 1 << 16
)

type PodOperateReplica struct {
	RepId     uint32             `json:"rep_id" toml:"rep_id"`
	Node      string             `json:"node,omitempty" toml:"node,omitempty"`
	Action    uint32             `json:"action,omitempty" toml:"action,omitempty"`
	ResCpu    int32              `json:"res_cpu,omitempty" toml:"res_cpu,omitempty"`         // in 1 = .1 Cores
	ResMem    int32              `json:"res_mem,omitempty" toml:"res_mem,omitempty"`         // in MiB
	VolSys    int32              `json:"vol_sys,omitempty" toml:"vol_sys,omitempty"`         // in GiB
	VolSysMnt string             `json:"vol_sys_mnt,omitempty" toml:"vol_sys_mnt,omitempty"` //
	Ports     ServicePorts       `json:"ports,omitempty" toml:"ports,omitempty"`
	Options   types.Labels       `json:"options,omitempty" toml:"options,omitempty"`
	Next      *PodOperateReplica `json:"next,omitempty" toml:"next,omitempty"`
	PrevNode  string             `json:"prev_node,omitempty" toml:"prev_node,omitempty"`
	Updated   uint32             `json:"updated,omitempty" toml:"updated,omitempty"`
	Scheduled uint32             `json:"scheduled,omitempty" toml:"scheduled,omitempty"`
}

func (it *PodOperateReplica) HostAddress(podId string) string {
	return PodRepInstanceName(podId, it.RepId)
}

type PodOperateReplicas []*PodOperateReplica

func (ls *PodOperateReplicas) Set(set PodOperateReplica) error {

	podOpMu.Lock()
	defer podOpMu.Unlock()

	for _, v := range *ls {
		if v.RepId == set.RepId {

			if set.Node != "" && set.Node != v.Node {
				v.Node = set.Node
			}

			v.Action = set.Action
			v.ResCpu = set.ResCpu
			v.ResMem = set.ResMem
			v.VolSys = set.VolSys
			v.VolSysMnt = set.VolSysMnt

			return nil
		}
	}

	*ls = append(*ls, &set)

	sort.Slice(*ls, func(i, j int) bool {
		return (*ls)[i].RepId < (*ls)[j].RepId
	})

	return nil
}

func (ls *PodOperateReplicas) Get(repId uint32) *PodOperateReplica {

	podOpMu.RLock()
	defer podOpMu.RUnlock()

	for _, v := range *ls {
		if v.RepId == repId {
			return v
		}
	}

	return nil
}

func (ls *PodOperateReplicas) Del(repId uint32) {

	podOpMu.Lock()
	defer podOpMu.Unlock()

	for i, v := range *ls {
		if v.RepId == repId {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *PodOperateReplicas) Sort() {
	podOpMu.Lock()
	sort.Slice(*ls, func(i, j int) bool {
		return (*ls)[i].RepId < (*ls)[j].RepId
	})
	podOpMu.Unlock()
}

type PodOperateAccess struct {
	SshOn  bool   `json:"ssh_on" toml:"ssh_on"`
	SshKey string `json:"ssh_key,omitempty" toml:"ssh_key,omitempty"`
	SshPwd string `json:"ssh_pwd,omitempty" toml:"ssh_pwd,omitempty"`
}
