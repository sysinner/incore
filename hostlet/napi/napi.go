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

package napi

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
)

const (
	NsOpLogHostletRepSync   = "hostlet/rep/sync"
	NsOpLogHostletRepAction = "hostlet/rep/action"
)

const (
	stats_tick          int64  = 5e9
	BoxStatsSampleCycle uint32 = 20
	BoxStatsLogCycle    uint32 = 60

	AgentBoxStatus = "%s/%s/home/action/.sysinner/box_status.json"
)

var (
	PodVolSysFmt       = "%s/%s"
	PodVolSysArchFmt   = "%s/%s.%s"
	VolPodHomeFmt      = "%s/%s/home/action"
	VolAgentSysDirFmt  = "%s/%s/home/action/.sysinner"
	BoxInstanceNameReg = regexp.MustCompile("^([0-9a-f]{16,24})-([0-9a-f]{4})$")
	StatsFeedNames     = []string{
		"ram/us", "ram/cc",
		"net/rs", "net/ws",
		"cpu/us",
		"fs/rn", "fs/rs", "fs/wn", "fs/ws",
	}
	LxcFsVols = []*inapi.PbVolumeMount{}
)

func ObjPrint(name string, v interface{}) {
	js, _ := json.Encode(v, "  ")
	fmt.Println("\n", name, string(js))
}

func VolPodHomeDir(podId string, repId uint32) string {
	return fmt.Sprintf(VolPodHomeFmt, config.Config.PodHomeDir,
		inapi.NsZonePodOpRepKey(podId, repId))
}

func PodVolSysDir(podId string, repId uint32) string {
	return fmt.Sprintf(PodVolSysFmt,
		config.Config.PodHomeDir,
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

func PodVolSysDirArch(podId string, repId uint32) string {
	return fmt.Sprintf(PodVolSysArchFmt,
		config.Config.PodHomeDir,
		time.Now().UTC().Format("20060102.150405"),
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

func VolAgentSysDir(podId string, repId uint32) string {
	return fmt.Sprintf(VolAgentSysDirFmt,
		config.Config.PodHomeDir,
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

type BoxDriver interface {
	Name() string
	Start() error
	Stop() error
	StatusEntry() *BoxInstance
	StatsEntry() *BoxInstanceStatsFeed
	BoxStart(box *BoxInstance) error
	BoxStop(box *BoxInstance) error
	BoxRemove(box *BoxInstance) error
}

type BoxDriverList struct {
	Items []BoxDriver
}

func (ls *BoxDriverList) Get(name string) BoxDriver {

	for _, dv := range ls.Items {
		if dv.Name() == name {
			return dv
		}
	}
	return nil
}

type BoxInstanceStatsEntry struct {
	Name  string
	Value int64
}

type BoxInstanceStatsFeed struct {
	Name  string
	Time  uint32
	Items []*BoxInstanceStatsEntry
}

func (it *BoxInstanceStatsFeed) Set(name string, value int64) {
	it.Items = append(it.Items, &BoxInstanceStatsEntry{
		Name:  name,
		Value: value,
	})
}

type BoxInstance struct {
	mu            sync.Mutex
	statusPending bool
	opPending     bool
	ID            string
	Name          string
	PodID         string
	PodOpVersion  uint32
	UpUpdated     uint32
	Spec          inapi.PodSpecBoxBound
	Apps          inapi.AppInstances
	Replica       inapi.PodOperateReplica
	Retry         int
	Env           []inapi.EnvVar
	Status        inapi.PbPodBoxStatus
	Stats         *inapi.PbStatsSampleFeed
}

func BoxInstanceName(podId string, repId uint32) string {

	if repId > 65535 {
		repId = 65535
	}

	return fmt.Sprintf(
		"%s-%s",
		podId, inutils.Uint16ToHexString(uint16(repId)),
	)
}

func BoxInstanceNameParse(hostname string) (podId string, repId uint32) {

	if ns := BoxInstanceNameReg.FindStringSubmatch(hostname); len(ns) >= 2 {

		rb, _ := hex.DecodeString(ns[2])
		repId = uint32(binary.BigEndian.Uint16(rb))

		return ns[1], repId
	}

	return "", 0
}

func (it *BoxInstance) OpLock() bool {

	it.mu.Lock()
	defer it.mu.Unlock()

	if it.opPending {
		return false
	}
	it.opPending = true

	return true
}

func (it *BoxInstance) OpUnlock() {

	it.mu.Lock()
	defer it.mu.Unlock()

	it.opPending = false
}

func (it *BoxInstance) StatusLock() bool {

	it.mu.Lock()
	defer it.mu.Unlock()

	if it.statusPending {
		return false
	}
	it.statusPending = true

	return true
}

func (it *BoxInstance) StatusUnlock() {

	it.mu.Lock()
	defer it.mu.Unlock()

	it.statusPending = false
}

func (inst *BoxInstance) OpRepKey() string {
	return inapi.NsZonePodOpRepKey(inst.PodID, inst.Replica.RepId)
}

func (inst *BoxInstance) SpecDesired() bool {

	if inst.Status.Action == 0 {
		hlog.Printf("debug", "box/spec miss-desire inst.Status.Action")
		return false
	}

	//
	if inst.Spec.Resources.CpuLimit != inst.Status.ResCpuLimit ||
		inst.Spec.Resources.MemLimit != inst.Status.ResMemLimit {
		hlog.Printf("debug", "box/spec miss-desire inst.Spec.Resources.Cpu/Mem")
		return false
	}

	if len(inst.Replica.Ports) != len(inst.Status.Ports) {
		hlog.Printf("debug", "box/spec miss-desire inst.Ports")
		return false
	}

	for _, v := range inst.Replica.Ports {

		mat := false
		for _, vd := range inst.Status.Ports {

			if uint32(v.BoxPort) != vd.BoxPort {
				continue
			}

			if v.HostPort > 0 && uint32(v.HostPort) != vd.HostPort {
				hlog.Printf("debug", "box/spec miss-desire inst.Ports")
				return false
			}

			mat = true
			break
		}

		if !mat {
			hlog.Printf("debug", "box/spec miss-desire inst.Ports")
			return false
		}
	}

	switch inst.Status.ImageDriver {
	case inapi.PbPodSpecBoxImageDriver_Docker:
	case inapi.PbPodSpecBoxImageDriver_Pouch:
		//
	default:
		hlog.Printf("debug", "box/spec miss-desire inst.Status.ImageOptions")
		return false
	}

	img2 := inapi.LabelSliceGet(inst.Status.ImageOptions, "image/id")
	if img2 == nil {
		hlog.Printf("debug", "box/spec miss-desire inst.Status.ImageOptions")
		return false
	}
	img1 := ""
	if inst.Spec.Image.Ref != nil {
		img1 = inst.Spec.Image.Ref.Id
		if strings.IndexByte(img1, ':') < 0 {
			img1 = inapi.BoxImageRepoDefault + ":" + img1
		}
	}
	if img1 != img2.Value {
		hlog.Printf("debug", "box/spec miss-desire inst.Status.ImageOptions (%s) (%s)",
			img1, img2.Value)
		return false
	}

	//
	if !inapi.PbVolumeMountSliceEqual(inst.Spec.Mounts, inst.Status.Mounts) {
		hlog.Printf("debug", "box/spec miss-desire inst.Spec.Mounts")
		return false
	}

	if len(inst.Spec.Command) != len(inst.Status.Command) ||
		strings.Join(inst.Spec.Command, " ") != strings.Join(inst.Status.Command, " ") {
		hlog.Printf("debug", "box/spec miss-desire inst.Spec.Command")
		return false
	}

	return true
}

func (inst *BoxInstance) OpActionDesired() bool {

	if inapi.OpActionDesire(inst.Replica.Action, inst.Status.Action) > 0 {
		return true
	}

	return false
}

func (inst *BoxInstance) VolumeMountsRefresh() {

	ls := []*inapi.PbVolumeMount{
		{
			Name:      "home",
			MountPath: "/home/action",
			HostDir:   VolPodHomeDir(inst.PodID, inst.Replica.RepId),
			ReadOnly:  false,
		},
		{
			Name:      "hosts",
			MountPath: "/etc/hosts",
			HostDir:   "/etc/hosts",
			ReadOnly:  true,
		},
		{
			Name:      "sysinner/nsz",
			MountPath: "/dev/shm/sysinner/nsz",
			HostDir:   "/dev/shm/sysinner/nsz",
			ReadOnly:  true,
		},
	}

	for _, app := range inst.Apps {

		if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionDestroy) {
			continue
		}

		for _, pkg := range app.Spec.Packages {

			ls, _ = inapi.PbVolumeMountSliceSync(ls, &inapi.PbVolumeMount{
				Name:      "ipm-" + pkg.Name,
				MountPath: InPackMountPath(pkg.Name, pkg.Version),
				HostDir:   InPackHostDir(pkg.Name, pkg.Version, pkg.Release, pkg.Dist, pkg.Arch),
				ReadOnly:  true,
			})
		}
	}

	if !inapi.PbVolumeMountSliceEqual(inst.Spec.Mounts, ls) {
		inst.Spec.Mounts = ls
	}
}

func (inst *BoxInstance) VolumeMountsExport() []string {

	bind_vols := []string{}

	for _, v := range inst.Spec.Mounts {

		bind_vol := v.HostDir + ":" + v.MountPath
		if v.ReadOnly {
			bind_vol += ":ro"
		} else {
			bind_vol += ":rw"
		}
		bind_vols = append(bind_vols, bind_vol)
	}

	return bind_vols
}

func (inst *BoxInstance) StatusActionSet(op uint32) {

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionMigrated) &&
		!inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) {
		inst.Status.Action = op | inapi.OpActionMigrated
	} else {
		inst.Status.Action = op
	}
}

var box_sets_mu sync.RWMutex

type BoxInstanceSets []*BoxInstance

func (ls *BoxInstanceSets) Get(name string) *BoxInstance {

	if name == "" {
		return nil
	}

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	for _, v := range *ls {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (ls *BoxInstanceSets) Set(item *BoxInstance) {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	for i, v := range *ls {
		if v.Name == item.Name {
			(*ls)[i] = item
			return
		}
	}

	*ls = append(*ls, item)
}

func (ls *BoxInstanceSets) Del(name string) {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	for i, v := range *ls {
		if v.Name == name {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *BoxInstanceSets) Size() int {

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	return len(*ls)
}

func (ls *BoxInstanceSets) Each(fn func(item *BoxInstance)) {

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	for _, v := range *ls {
		fn(v)
	}
}

func (ls *BoxInstanceSets) OpLockNum() int {
	n := 0
	for _, v := range *ls {
		if v.opPending {
			n += 1
		}
	}
	return n
}

type RsyncModuleItem struct {
	User string `json:"user"`
	Dir  string `json:"dir"`
}
