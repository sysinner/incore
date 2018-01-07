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
	"regexp"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	pod_op_mu        sync.RWMutex
	pod_sets_mu      sync.RWMutex
	pod_st_mu        sync.RWMutex
	PodIdReg         = regexp.MustCompile("^[a-f0-9]{16,24}$")
	PodSpecPlanIdReg = regexp.MustCompile("^[a-z]{1}[a-z0-9]{1,9}$")
)

const (
	PodSpecBoxImageDocker = "docker"
	PodSpecBoxImageRockit = "rkt"
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

// Pod is a collection of boxes, used as either input (create, update) or as output (list, get).
type Pod struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	// Spec defines the behavior of a pod.
	Spec *PodSpecBound `json:"spec,omitempty"`

	//
	Operate PodOperate `json:"operate,omitempty"`

	// Apps represents the information about a collection of applications to deploy.
	// this is a module for App Engine
	Apps AppInstances `json:"apps,omitempty"`

	// Status represents the current information about a pod. This data may not be up
	// to date.
	Status *PodStatus `json:"status,omitempty"`

	//
	Payment *PodPayment `json:"payment,omitempty"`
}

type PodPayment struct {
	TimeStart   uint32  `json:"time_start"`
	TimeClose   uint32  `json:"time_close"`
	Prepay      float64 `json:"prepay"`
	Payout      float64 `json:"payout"`
	CycleAmount float64 `json:"cycle_amount"`
}

type PodEstimateList struct {
	types.TypeMeta `json:",inline"`
	Items          []*PodEstimateEntry `json:"items"`
}

type PodEstimateEntry struct {
	Name        string  `json:"name"`
	CycleAmount float64 `json:"cycle_amount"`
	CycleTime   uint64  `json:"cycle_time"`
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

func (pod *Pod) OpRepKey() string {
	if pod.Operate.Replica == nil {
		return NsZonePodOpRepKey(pod.Meta.ID, 0)
	}
	return NsZonePodOpRepKey(pod.Meta.ID, pod.Operate.Replica.Id)
}

func (pod *Pod) IterKey() string {
	return pod.OpRepKey()
}

type PodSets []*Pod

func (ls *PodSets) Get(key string) *Pod {
	pod_sets_mu.RLock()
	defer pod_sets_mu.RUnlock()
	for _, v := range *ls {
		if v.IterKey() == key {
			return v
		}
	}
	return nil
}

func (ls *PodSets) Set(item *Pod) {
	pod_sets_mu.Lock()
	defer pod_sets_mu.Unlock()

	for i, v := range *ls {
		if v.IterKey() == item.IterKey() {
			(*ls)[i] = item
			return
		}
	}
	*ls = append(*ls, item)
}

func (ls *PodSets) Del(key string) {
	pod_sets_mu.Lock()
	defer pod_sets_mu.Unlock()
	for i, v := range *ls {
		if v.IterKey() == key {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *PodSets) Each(fn func(item *Pod)) {
	pod_sets_mu.RLock()
	defer pod_sets_mu.RUnlock()

	for _, v := range *ls {
		fn(v)
	}
}

// PodList is a list of Pods.
type PodList struct {
	types.TypeMeta `json:",inline"`
	Items          []Pod `json:"items"`
}

// PodSpecBound is a description of a bound spec based on PodSpecPlan
type PodSpecBound struct {
	Ref     ObjectReference         `json:"ref,omitempty"`
	Zone    string                  `json:"zone,omitempty"`
	Cell    string                  `json:"cell,omitempty"`
	Labels  types.Labels            `json:"labels,omitempty"`
	Volumes []PodSpecResVolumeBound `json:"volumes,omitempty"`
	Boxes   []PodSpecBoxBound       `json:"boxes,omitempty"`
}

func (obj *PodSpecBound) Volume(name string) *PodSpecResVolumeBound {

	for _, v := range obj.Volumes {

		if v.Name == name {
			return &v
		}
	}

	return nil
}

func (obj *PodSpecBound) ResComputeBound() *PodSpecBoxResComputeBound {

	rs := &PodSpecBoxResComputeBound{}

	for _, v := range obj.Boxes {

		if v.Resources == nil {
			continue
		}

		rs.CpuLimit += v.Resources.CpuLimit
		rs.MemLimit += v.Resources.MemLimit
	}

	return rs
}

type PodSpecBoundList struct {
	types.TypeMeta `json:",inline"`
	Items          []PodSpecBound `json:"items,omitempty"`
}

// ObjectReference contains enough information to let you inspect or modify the referred object
type ObjectReference struct {
	Id      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
}

type PodSpecResVolumeBound struct {
	Ref       ObjectReference `json:"ref,omitempty"`
	Name      string          `json:"name"`
	Labels    types.Labels    `json:"labels,omitempty"`
	SizeLimit int64           `json:"size_limit,omitempty"`
}

type PodSpecBoxBound struct {
	Name      string                     `json:"name"`
	Image     PodSpecBoxImageBound       `json:"image,omitempty"`
	Resources *PodSpecBoxResComputeBound `json:"resources,omitempty"`
	Mounts    []*PbVolumeMount           `json:"mounts,omitempty"`
	Ports     Ports                      `json:"ports,omitempty"`
	Command   []string                   `json:"command,omitempty"`
	Updated   types.MetaTime             `json:"updated,omitempty"`
}

type PodSpecBoxImageBound struct {
	Ref    *ObjectReference `json:"ref,omitempty"`
	Driver string           `json:"driver,omitempty"`

	Options types.Labels `json:"options,omitempty"`

	// Distribution short name of the operating system.
	//  ex: el6, el7, deb7, ubu1404, ...
	OsDist string `json:"os_dist,omitempty"`

	// A human-readable description of the operating system.
	// OsName string `json:"os_name,omitempty"`

	// Architecture indicates the type of hardware.
	//  ex: amd64, armv6l, ...
	Arch string `json:"arch,omitempty"`
}

type PodSpecBoxResComputeBound struct {
	Ref      *ObjectReference `json:"ref,omitempty"`
	CpuLimit int64            `json:"cpu_limit,omitempty"`
	MemLimit int64            `json:"mem_limit,omitempty"`
}

type PodSpecBoxImage struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	Status string `json:"status,omitempty"`

	// Container type of the image.
	//  ex: docker, rkt, ...
	Driver string `json:"driver,omitempty"`

	// TODO
	AccessRoles string `json:"access_roles,omitempty"`

	// Options are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "docker/image/name", value: "centos/lastest"},
	//  {name: "example.com/spec/name", value: "hello"}, ...
	Options types.Labels `json:"options,omitempty"`

	// Annotations are name value pairs that representing additional information,
	// any extra metadata you wish may be added to the list.
	// ex:
	//  {name: "homepage", value: "http://example.com"}, ...
	Annotations types.Labels `json:"annotations,omitempty"`

	// Type name of the operating system.
	//  ex: linux, freebsd, darwin, ...
	OsType string `json:"os_type,omitempty"`

	// Distribution short name of the operating system.
	//  ex: el6, el7, deb7, ubu1404, ...
	OsDist string `json:"os_dist,omitempty"`

	// Version of the operating system.
	OsVersion string `json:"os_version,omitempty"`

	// A human-readable description of the operating system.
	OsName string `json:"os_name,omitempty"`

	// Architecture indicates the type of hardware.
	//  ex: amd64, armv6l, ...
	Arch string `json:"arch,omitempty"`
}

type PodSpecBoxImageList struct {
	types.TypeMeta `json:",inline"`
	Items          []PodSpecBoxImage `json:"items,omitempty"`
}

type PodSpecResCompute struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	Status string `json:"status,omitempty"`

	// Labels are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "plan/name", value: "general"}, ...
	Labels types.Labels `json:"labels,omitempty"`

	// CPU, in cores. (500 = .5 cores)
	CpuLimit int64 `json:"cpu_limit,omitempty"`

	// Memory, in bytes.
	MemLimit int64 `json:"mem_limit,omitempty"`
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
	types.TypeMeta `json:",inline"`
	Items          PodSpecResComputes `json:"items,omitempty"`
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
	Type  uint8   `json:"type"`
	Cycle uint64  `json:"cycle"` // default to 3600 seconds
	Cpu   float64 `json:"cpu"`   // value in Core
	Mem   float64 `json:"mem"`   // value in MiB
}

type PodSpecResVolume struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	Status string `json:"status,omitempty"`

	// Labels are name value pairs that representing extensional information,
	// usually be used in special system components, names must be unique within the list.
	// ex:
	//  {name: "plan/name", value: "general"}, ...
	Labels types.Labels `json:"labels,omitempty"`

	// Volume size, in bytes.
	Limit   int64 `json:"limit,omitempty"`   // max to 2000GB
	Request int64 `json:"request,omitempty"` // start from 100MB
	Step    int64 `json:"step,omitempty"`    // every step by 100MB
	Default int64 `json:"default,omitempty"` // default to 100MB
}

type PodSpecResVolumeList struct {
	types.TypeMeta `json:",inline"`
	Items          []PodSpecResVolume `json:"items,omitempty"`
}

type PodSpecResVolumeCharge struct {
	Type    uint8   `json:"type"`
	Cycle   uint64  `json:"cycle"`    // default to 3600 seconds
	CapSize float64 `json:"cap_size"` // value in MiB
}

// TODO
type PodSpecResourceNetwork struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`
}

// TODO
type PodSpecResourceNetworkList struct {
	types.TypeMeta `json:",inline"`
	Items          []PodSpecResourceNetwork `json:"items,omitempty"`
}

type PodSpecPlanResourceCharge struct {
	Type  uint8  `json:"type"`
	Cycle uint64 `json:"cycle"` // default to 3600 seconds
}

type PodSpecPlanBoxImageBound struct {
	RefId   string       `json:"ref_id"`
	Driver  string       `json:"driver,omitempty"`
	Options types.Labels `json:"options,omitempty"`
	OsDist  string       `json:"os_dist,omitempty"`
	Arch    string       `json:"arch,omitempty"`
}

type PodSpecPlanResComputeBound struct {
	RefId    string `json:"ref_id"`
	CpuLimit int64  `json:"cpu_limit"`
	MemLimit int64  `json:"mem_limit"`
}

type PodSpecPlanResVolumeBound struct {
	RefId   string       `json:"ref_id"`
	Limit   int64        `json:"limit,omitempty"`   // max to 2000GB
	Request int64        `json:"request,omitempty"` // start from 100MB
	Step    int64        `json:"step,omitempty"`    // every step by 100MB
	Default int64        `json:"default,omitempty"` // default to 100MB
	Labels  types.Labels `json:"labels,omitempty"`
}

type PodSpecPlan struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	Status    string                  `json:"status,omitempty"`
	Zones     []*PodSpecPlanZoneBound `json:"zones,omitempty"`
	SortOrder int                     `json:"sort_order"`

	Labels      types.Labels `json:"labels,omitempty"`
	Annotations types.Labels `json:"annotations,omitempty"`

	Images       []*PodSpecPlanBoxImageBound `json:"images,omitempty"`
	ImageDefault string                      `json:"image_default,omitempty"`

	ResComputes       PodSpecPlanResComputeBounds `json:"res_computes,omitempty"`
	ResComputeDefault string                      `json:"res_compute_default,omitempty"`
	ResComputeCharge  PodSpecResComputeCharge     `json:"res_compute_charge,omitempty"`

	ResVolumes       []*PodSpecPlanResVolumeBound `json:"res_volumes,omitempty"`
	ResVolumeDefault string                       `json:"res_volume_default,omitempty"`
	ResVolumeCharge  PodSpecResVolumeCharge       `json:"res_volume_charge,omitempty"`

	ResourceCharge PodSpecPlanResourceCharge `json:"res_charge"`
}

// TODO
func (s *PodSpecPlan) ChargeFix() {

	s.ResourceCharge.Cycle = 3600

	s.ResComputeCharge.Cpu = 0.1
	s.ResComputeCharge.Mem = 0.0001

	s.ResVolumeCharge.CapSize = 0.000004
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

type PodSpecPlanList struct {
	types.TypeMeta `json:",inline"`
	Items          []*PodSpecPlan `json:"items,omitempty"`
}

func (ls *PodSpecPlanList) Get(plan_id string) *PodSpecPlan {
	for _, v := range ls.Items {
		if v.Meta.ID == plan_id {
			return v
		}
	}

	return nil
}

type PodSpecPlanZoneBound struct {
	Name  string            `json:"name,omitempty"`
	Cells types.ArrayString `json:"cells,omitempty"`
}

type PodCreate struct {
	types.TypeMeta `json:",inline"`
	Pod            string         `json:"pod,omitempty"`
	Name           string         `json:"name"`
	Plan           string         `json:"plan"`
	Zone           string         `json:"zone"`
	Cell           string         `json:"cell"`
	ResVolume      string         `json:"res_volume"`
	ResVolumeSize  int64          `json:"res_volume_size"`
	Boxes          []PodCreateBox `json:"boxes"`
}

type PodCreateBox struct {
	Name               string `json:"name"`
	Image              string `json:"image"`
	ResCompute         string `json:"res_compute"`
	ResComputeCpuLimit int64  `json:"res_compute_cpu_limit,omitempty"`
	ResComputeMemLimit int64  `json:"res_compute_mem_limit,omitempty"`
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

	if s.ResVolumeSize < 100*ByteMB {
		return errors.New("Invalid ResVolumeSize")
	}

	if s.ResVolumeSize >= ByteGB {

		if fix := s.ResVolumeSize % ByteGB; fix > 0 {
			s.ResVolumeSize -= fix
		}

	} else if fix := s.ResVolumeSize % ByteMB; fix > 0 {
		s.ResVolumeSize -= fix
	}

	for _, vol := range plan.ResVolumes {

		if vol.RefId != s.ResVolume {
			continue
		}

		if s.ResVolumeSize > vol.Limit ||
			s.ResVolumeSize < vol.Request {
			return errors.New("Invalid ResVolumeSize")
		}

		hit = true
		break
	}

	if !hit {
		return errors.New("No ResVolume Found")
	}

	for i, box := range s.Boxes {

		hit = false

		for _, rv := range plan.ResComputes {

			if rv.RefId != box.ResCompute {
				continue
			}

			s.Boxes[i].ResComputeCpuLimit = rv.CpuLimit
			s.Boxes[i].ResComputeMemLimit = rv.MemLimit

			hit = true
			break
		}

		if !hit {
			return errors.New("Invalid ResCompute")
		}
	}

	return nil
}

type PodOperate struct {
	Action     uint32             `json:"action,omitempty"`
	Version    uint32             `json:"version,omitempty"`
	ReplicaCap int                `json:"replica_cap,omitempty"`
	Replicas   PodOperateReplicas `json:"replicas,omitempty"`
	Replica    *PodOperateReplica `json:"replica,omitempty"`
	OpLog      []*PbOpLogEntry    `json:"op_log,omitempty"`
	Operated   uint32             `json:"operated,omitempty"`
	Access     *PodOperateAccess  `json:"access,omitempty"`
}

type PodOperateReplica struct {
	Id    uint16       `json:"id"`
	Node  string       `json:"node,omitempty"`
	Ports ServicePorts `json:"ports,omitempty"`
}

type PodOperateReplicas []*PodOperateReplica

func (ls *PodOperateReplicas) InitScheduled() bool {
	for _, v := range *ls {
		if v.Node != "" {
			return true
		}
	}
	return false
}

func (ls *PodOperateReplicas) CapacitySet(n int) {

	pod_op_mu.Lock()
	defer pod_op_mu.Unlock()

	if len(*ls) > 0 {
		return
	}

	if n < 1 {
		n = 1
	} else if n > 4096 {
		n = 4096
	}

	for id := uint16(0); id < uint16(n); id++ {
		*ls = append(*ls, &PodOperateReplica{
			Id:   id,
			Node: "",
		})
	}
}

func (ls *PodOperateReplicas) Set(set PodOperateReplica) error {

	pod_op_mu.Lock()
	defer pod_op_mu.Unlock()

	for _, v := range *ls {
		if v.Id == set.Id {
			if set.Node != "" && set.Node != v.Node {
				v.Node = set.Node
			}
			return nil
		}
	}

	return errors.New("No Replica Found")
}

func (ls *PodOperateReplicas) Get(rep_id uint16) *PodOperateReplica {

	pod_op_mu.RLock()
	defer pod_op_mu.RUnlock()

	for _, v := range *ls {
		if v.Id == rep_id {
			return v
		}
	}

	return nil
}

type PodOperateAccess struct {
	SshOn  bool   `json:"ssh_on"`
	SshKey string `json:"ssh_key,omitempty"`
}

type PodExecutorStatus struct {
	types.TypeMeta `json:",inline"`
	Items          ExecutorStatuses `json:"items"`
}

// PodStatus represents information about the status of a pod. Status may trail the actual
// state of a system.
type PodStatus struct {
	types.TypeMeta `json:",inline"`
	Action         uint32            `json:"action,omitempty"`
	Replicas       []*PbPodRepStatus `json:"replicas,omitempty"`
	Updated        uint32            `json:"updated,omitempty"`
	OpLog          []*PbOpLogEntry   `json:"op_log,omitempty"`
}

func (it *Pod) StatusRefresh() {
	it.Status.Refresh(it.Operate.ReplicaCap)
}

func (it *PodStatus) Refresh(rep_cap int) {

	if rep_cap != len(it.Replicas) {

		it.Action = OpActionPending

	} else {

		s_diff := map[uint32]int{}

		for _, rep := range it.Replicas {

			if rep.Updated > it.Updated {
				it.Updated = rep.Updated
			}

			if OpActionAllow(rep.Action, OpActionRunning) {
				s_diff[OpActionRunning]++
			} else if OpActionAllow(rep.Action, OpActionStopped) {
				s_diff[OpActionStopped]++
			} else if OpActionAllow(rep.Action, OpActionDestroyed) {
				s_diff[OpActionDestroyed]++
			} else if OpActionAllow(rep.Action, OpActionWarning) {
				s_diff[OpActionWarning]++
			} else {
				s_diff[OpActionPending]++
			}
		}

		if len(s_diff) == 1 {

			for k := range s_diff {
				it.Action = k
				break
			}

		} else if _, ok := s_diff[OpActionWarning]; ok {
			it.Action = OpActionWarning
		} else {
			it.Action = OpActionPending
		}
	}
}
