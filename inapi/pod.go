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
	"regexp"
	"sort"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	podOpMu          sync.RWMutex
	podItemsMu       sync.RWMutex
	pod_st_mu        sync.RWMutex
	PodIdReg         = regexp.MustCompile("^[a-f0-9]{16,24}$")
	PodSpecPlanIdReg = regexp.MustCompile("^[a-z]{1}[a-z0-9]{1,9}$")
	PodDestroyTTL    = uint32(86400)
)

const (
	PodSpecBoxImageDocker = "docker"
	PodSpecBoxImageRkt    = "rkt"
	PodSpecBoxImagePouch  = "pouch"
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

// Pod is a collection of containers, used as either input (create, update) or as output (list, get).
type Pod struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	// Spec defines the behavior of a pod.
	Spec *PodSpecBound `json:"spec,omitempty"`

	// Apps represents the information about a collection of applications to deploy.
	// this is a module for App Engine
	Apps AppInstances `json:"apps,omitempty"`

	//
	Operate PodOperate `json:"operate,omitempty"`

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

func (pod *Pod) OpRepCapValid(num_new int) error {

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

func (pod *Pod) OpSysStateValid(state_new int) error {

	if state_new != pod.Operate.ExpSysState {
		if pod.Apps != nil &&
			pod.Apps.SpecExpDeployIsStateful() &&
			state_new == AppSpecExpDeploySysStateless {
			return errors.New("State conflict with AppSpec")
		}
	}

	return nil
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

		//
		specVol := pod.Spec.Volume("system")
		if specVol == nil {
			return false
		}

		//
		destRes := pod.Spec.ResComputeBound()
		cpu, mem = destRes.CpuLimit, destRes.MemLimit
	}

	destNum := 0

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
	types.TypeMeta `json:",inline"`
	Items          PodItems `json:"items"`
}

// PodSpecBound is a description of a bound spec based on PodSpecPlan
type PodSpecBound struct {
	Ref       ObjectReference         `json:"ref,omitempty"`
	Zone      string                  `json:"zone,omitempty"`
	Cell      string                  `json:"cell,omitempty"`
	BoxDriver string                  `json:"box_driver,omitempty"`
	Labels    types.Labels            `json:"labels,omitempty"`
	Volumes   []PodSpecResVolumeBound `json:"volumes,omitempty"`
	Box       PodSpecBoxBound         `json:"box,omitempty"`
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

	if obj != nil {

		if obj.Box.Resources != nil {
			rs.CpuLimit = obj.Box.Resources.CpuLimit
			rs.MemLimit = obj.Box.Resources.MemLimit
		}
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
	SizeLimit int32           `json:"size_limit,omitempty"` // in GiB
}

type PodSpecBoxBound struct {
	Name      string                     `json:"name,omitempty"`
	Image     PodSpecBoxImageBound       `json:"image,omitempty"`
	Resources *PodSpecBoxResComputeBound `json:"resources,omitempty"`
	Mounts    []*PbVolumeMount           `json:"mounts,omitempty"`
	Ports     Ports                      `json:"ports,omitempty"`
	Command   []string                   `json:"command,omitempty"`
	Updated   types.MetaTime             `json:"updated,omitempty"`
}

type PodSpecBoxImageBound struct {
	Ref *ObjectReference `json:"ref,omitempty"`

	Driver string `json:"driver,omitempty"`

	// Options types.Labels `json:"options,omitempty"`

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
	CpuLimit int32            `json:"cpu_limit,omitempty"` // in .1 Cores
	MemLimit int32            `json:"mem_limit,omitempty"` // in MiB
}

type PodSpecBoxImage struct {
	types.TypeMeta `json:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty"`

	Status string `json:"status,omitempty"`

	// Container type of the image.
	//  ex: docker, rkt, pouch.
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

	// CPU, in Cores. (1 = .1 Cores)
	CpuLimit int32 `json:"cpu_limit,omitempty"`

	// Memory, in MiB
	MemLimit int32 `json:"mem_limit,omitempty"`
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
	Cpu   float64 `json:"cpu"`   // value in Cores
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

	// Volume size, in GiB.
	Limit   int32 `json:"limit,omitempty"`   // max to 1000 GB
	Request int32 `json:"request,omitempty"` // start from 1 GiB
	Step    int32 `json:"step,omitempty"`    // every step by 1 GiB
	Default int32 `json:"default,omitempty"` // default to 1 GiB
}

type PodSpecResVolumeList struct {
	types.TypeMeta `json:",inline"`
	Items          []PodSpecResVolume `json:"items,omitempty"`
}

type PodSpecResVolumeCharge struct {
	Type    uint8   `json:"type"`
	Cycle   uint64  `json:"cycle"`    // default to 3600 seconds
	CapSize float64 `json:"cap_size"` // value in GiB
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
	RefId  string `json:"ref_id"`
	Driver string `json:"driver,omitempty"`
	OsDist string `json:"os_dist,omitempty"`
	Arch   string `json:"arch,omitempty"`
	// Options types.Labels `json:"options,omitempty"`
}

type PodSpecPlanResComputeBound struct {
	RefId    string `json:"ref_id"`
	CpuLimit int32  `json:"cpu_limit"` // in .1 Cores
	MemLimit int32  `json:"mem_limit"` // in MiB
}

type PodSpecPlanResVolumeBound struct {
	RefId   string       `json:"ref_id"`
	Limit   int32        `json:"limit,omitempty"`   // max to 2000 GB
	Request int32        `json:"request,omitempty"` // start from 1 GiB
	Step    int32        `json:"step,omitempty"`    // every step by 1 GiB
	Default int32        `json:"default,omitempty"` // default to 1 GiB
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
	s.ResComputeCharge.Cpu = 0.1       // 0.07778
	s.ResComputeCharge.Mem = 0.0001    // 0.00005
	s.ResVolumeCharge.CapSize = 0.0005 // 0.0004
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
	types.TypeMeta `json:",inline"`
	Items          PodSpecPlans `json:"items,omitempty"`
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
	Name  string            `json:"name,omitempty"`
	Cells types.ArrayString `json:"cells,omitempty"`
}

type PodCreate struct {
	types.TypeMeta `json:",inline"`
	Pod            string       `json:"pod,omitempty"`
	Name           string       `json:"name"`
	Plan           string       `json:"plan"`
	Zone           string       `json:"zone"`
	Cell           string       `json:"cell"`
	ResVolume      string       `json:"res_volume"`
	ResVolumeSize  int32        `json:"res_volume_size"` // in GiB
	Box            PodCreateBox `json:"box"`
}

type PodCreateBox struct {
	Name               string `json:"name"`
	Image              string `json:"image"`
	ResCompute         string `json:"res_compute"`
	ResComputeCpuLimit int32  `json:"res_compute_cpu_limit,omitempty"` // in .1 Cores
	ResComputeMemLimit int32  `json:"res_compute_mem_limit,omitempty"` // in MiB
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
	Action       uint32                   `json:"action,omitempty"`
	Version      uint32                   `json:"version,omitempty"`
	Priority     int                      `json:"priority,omitempty"` // TODO
	ReplicaCap   int                      `json:"replica_cap,omitempty"`
	Replicas     PodOperateReplicas       `json:"replicas,omitempty"`
	RepMigrates  []uint32                 `json:"rep_migrates,omitempty"`
	OpLog        []*PbOpLogEntry          `json:"op_log,omitempty"`
	Operated     uint32                   `json:"operated,omitempty"`
	Access       *PodOperateAccess        `json:"access,omitempty"`
	ExpSysState  int                      `json:"exp_sys_state,omitempty"`
	BindServices []*AppServicePortPodBind `json:"bind_services,omitempty"`
}

var (
	PodOpRepActStart          = OpActionStart
	PodOpRepActStop           = OpActionStop
	PodOpRepActFree           = OpActionDestroy
	PodOpRepActMigrate        = OpActionMigrate
	PodOpRepActWait    uint32 = 1 << 16
)

type PodOperateReplica struct {
	RepId    uint32             `json:"rep_id"`
	Node     string             `json:"node,omitempty"`
	Action   uint32             `json:"action,omitempty"`
	ResCpu   int32              `json:"res_cpu,omitempty"` // in 1 = .1 Cores
	ResMem   int32              `json:"res_mem,omitempty"` // in MiB
	VolSys   int32              `json:"vol_sys,omitempty"` // in GiB
	Ports    ServicePorts       `json:"ports,omitempty"`
	Options  types.Labels       `json:"options,omitempty"`
	Next     *PodOperateReplica `json:"next,omitempty"`
	PrevNode string             `json:"prev_node,omitempty"`
	Updated  uint32             `json:"updated,omitempty"`
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
	SshOn  bool   `json:"ssh_on"`
	SshKey string `json:"ssh_key,omitempty"`
	SshPwd string `json:"ssh_pwd,omitempty"`
}

type PodExecutorStatus struct {
	types.TypeMeta `json:",inline"`
	Items          ExecutorStatuses `json:"items"`
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
	types.TypeMeta `json:",inline"`
	PodId          string          `json:"pod_id,omitempty"`
	Action         uint32          `json:"action,omitempty"`
	ActionRunning  int             `json:"action_running"`
	Replicas       PodRepStatuses  `json:"replicas,omitempty"`
	Updated        uint32          `json:"updated,omitempty"`
	OpLog          []*PbOpLogEntry `json:"op_log,omitempty"`
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

type PodStatusList struct {
	mu    sync.RWMutex
	Items []*PodStatus `json:"items"`
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
