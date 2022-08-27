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
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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

	AgentBoxStatusFmt = "%s/%s/home/action/.sysinner/box_status.json"
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

func volMountPoint(mnt string) string {
	if strings.HasPrefix(mnt, "/data/") ||
		strings.HasPrefix(mnt, "/opt") {
		mnt += "/sysinner/pods"
	} else if mnt == "" {
		mnt = config.Config.Zone.PodHomeDir
	}
	if runtime.GOOS == "darwin" && !strings.HasPrefix(mnt, "/Volumes/") {
		return "/Volumes" + mnt
	}
	return mnt
}

func AgentBoxStatus(mnt, podId string, repId uint32) string {
	return filepath.Clean(fmt.Sprintf(AgentBoxStatusFmt,
		volMountPoint(mnt),
		inapi.NsZonePodOpRepKey(podId, repId),
	))
}

func VolPodPath(mnt string, podId string, repId uint32, path string) string {
	return filepath.Clean(fmt.Sprintf(PodVolSysFmt,
		volMountPoint(mnt),
		inapi.NsZonePodOpRepKey(podId, repId),
	) + "/" + path)
}

func VolPodHomeDir(mnt string, podId string, repId uint32) string {
	return filepath.Clean(fmt.Sprintf(VolPodHomeFmt,
		volMountPoint(mnt),
		inapi.NsZonePodOpRepKey(podId, repId)))
}

func PodVolSysDir(mnt string, podId string, repId uint32) string {
	return fmt.Sprintf(PodVolSysFmt,
		volMountPoint(mnt),
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

func PodVolSysDirArch(mnt string, podId string, repId uint32) string {
	return fmt.Sprintf(PodVolSysArchFmt,
		volMountPoint(mnt),
		time.Now().UTC().Format("20060102.150405"),
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

func VolAgentSysDir(mnt string, podId string, repId uint32) string {
	return fmt.Sprintf(VolAgentSysDirFmt,
		volMountPoint(mnt),
		inapi.NsZonePodOpRepKey(podId, repId),
	)
}

type BoxDriver interface {
	Name() string
	Start() error
	Stop() error
	StatusList() []*BoxInstance
	StatsList() []*BoxInstanceStatsFeed
	ImageSetup(box *BoxInstance) error
	BoxCreate(box *BoxInstance) error
	BoxStart(box *BoxInstance) error
	BoxStop(box *BoxInstance) error
	BoxRemove(box *BoxInstance) error
	BoxExist(box *BoxInstance) (bool, error)
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

type BoxPackMount struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	HostPath string `json:"host_path"`
}

const (
	blockLimitBpsMin  int64 = 32 << 20
	blockLimitBpsMax  int64 = 256 << 20
	blockLimitIOpsMin int64 = 100
	blockLimitIOpsMax int64 = 10000
	blockLimitRange   int32 = 1000
)

var (
	blockLimitBpsRate  = float64(blockLimitBpsMax-blockLimitBpsMin) / float64(blockLimitRange)
	blockLimitIOpsRate = float64(blockLimitIOpsMax-blockLimitIOpsMin) / float64(blockLimitRange)
)

type BoxInstance struct {
	mu              sync.Mutex
	statusPending   bool
	opPending       bool
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	PodID           string                     `json:"pod_id"`
	PodOpVersion    uint32                     `json:"pod_op_version"`
	UpUpdated       uint32                     `json:"up_updated"`
	Spec            inapi.PodSpecBoxBound      `json:"spec"`
	Apps            inapi.AppInstances         `json:"apps"`
	Replica         inapi.PodOperateReplica    `json:"replica"`
	Retry           int                        `json:"retry"`
	Env             []inapi.EnvVar             `json:"env"`
	Status          inapi.PbPodBoxStatus       `json:"status"`
	HealthStatus    inapi.HealthStatus         `json:"health_status"`
	Stats           *inapi.PbStatsSampleFeed   `json:"-"`
	SysVolSynced    int64                      `json:"sys_vol_synced"`
	SpecCpuSets     []int32                    `json:"spec_cpu_sets"`
	SpecMounts      []*inapi.PodSpecBoundMount `json:"spec_mounts"`
	PackMounts      []*BoxPackMount            `json:"pack_mounts"`
	SetupHosts      []string                   `json:"setup_hosts"`
	BlkioDeviceBps  int64                      `json:"blkio_device_bps"`  // bytes per second
	BlkioDeviceIOps int64                      `json:"blkio_device_iops"` // IO per second
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

	//
	if inst.Spec.Resources.CpuLimit != inst.Status.ResCpuLimit ||
		inst.Spec.Resources.MemLimit != inst.Status.ResMemLimit {
		hlog.Printf("info", "box/spec miss-desire inst.Spec.Resources.Cpu/Mem")
		return false
	}

	if len(inst.Replica.Ports) != len(inst.Status.Ports) {
		hlog.Printf("info", "box/spec miss-desire inst.Ports")
		return false
	}

	if inst.Apps.NetworkModeHost() {
		if inst.Status.NetworkMode != inapi.AppSpecExpDeployNetworkModeHost {
			hlog.Printf("info", "box/spec miss-desire inst.deploy.network.mode")
			return false
		}
	} else {
		if runtime.GOOS == "linux" &&
			inst.Replica.VpcIpv4 != "" &&
			inst.Replica.VpcIpv4 != inst.Status.NetworkIpv4 {
			hlog.Printf("info", "box/spec miss-desire inst.network.vpc_ipv4")
			return false
		}
	}

	hosts := inst.ExtHosts(false)
	if !inapi.ArrayStringEqual(inst.SetupHosts, hosts) {
		hlog.Printf("info", "box/spec miss-desire inst.hosts")
		return false
	}

	for _, v := range inst.Replica.Ports {

		mat := false

		for _, vd := range inst.Status.Ports {

			if uint32(v.BoxPort) != vd.BoxPort {
				continue
			}

			if v.HostPort > 0 && uint32(v.HostPort) != vd.HostPort {
				hlog.Printf("info", "box/spec miss-desire inst.Ports")
				return false
			}

			mat = true
			break
		}

		if !mat {
			hlog.Printf("info", "box/spec miss-desire inst.Ports")
			return false
		}
	}

	switch inst.Status.ImageDriver {
	case inapi.PbPodSpecBoxImageDriver_Docker:
	case inapi.PbPodSpecBoxImageDriver_Pouch:
		//
	default:
		hlog.Printf("info", "box/spec miss-desire inst.Status.ImageOptions")
		return false
	}

	img2 := inapi.LabelSliceGet(inst.Status.ImageOptions, "image/id")
	if img2 == nil {
		hlog.Printf("info", "box/spec miss-desire inst.Status.ImageOptions")
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
		hlog.Printf("info", "box/spec miss-desire inst.Status.ImageOptions (%s) (%s)",
			img1, img2.Value)
		return false
	}

	//
	if !inapi.PbVolumeMountSliceEqual(inst.Spec.Mounts, inst.Status.Mounts) {
		hlog.Printf("info", "box/spec miss-desire inst.Spec.Mounts %v, %v",
			inst.Spec.Mounts, inst.Status.Mounts)
		return false
	}

	//
	if inst.BlkioDeviceBps > 0 && inst.BlkioDeviceIOps > 0 &&
		len(inst.Status.BlkioDeviceLimits) > 0 {
		for _, v := range inst.Status.BlkioDeviceLimits {
			if v.ReadBps != inst.BlkioDeviceBps ||
				v.ReadIops != inst.BlkioDeviceIOps ||
				v.WriteBps != inst.BlkioDeviceBps ||
				v.WriteIops != inst.BlkioDeviceIOps {
				hlog.Printf("info", "box/spec miss-desire inst.Spec.BlkioDevice limits")
				return false
			}
		}
	}

	if len(inst.Spec.Command) != len(inst.Status.Command) ||
		strings.Join(inst.Spec.Command, " ") != strings.Join(inst.Status.Command, " ") {
		hlog.Printf("info", "box/spec miss-desire inst.Spec.Command")
		return false
	}

	if runtime.GOOS == "linux" && !ArrayInt32Equal(inst.SpecCpuSets, inst.Status.CpuSets) {
		hlog.Printf("info", "box/spec miss-desire inst.CpuSets")
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

func (inst *BoxInstance) ExtHosts(excludeRep bool) []string {

	hosts := []string{}
	hostMap := map[string]string{
		PodRepNetworkDomainName(inst.PodID, inst.Replica.RepId): "127.0.0.1",
	}

	for _, app := range inst.Apps {

		for _, srv := range app.Operate.Services {

			if len(srv.Endpoints) < 1 {
				continue
			}

			podId := srv.PodId
			if podId == "" {
				podId = inst.PodID
			}

			for _, ep := range srv.Endpoints {

				domain := PodRepNetworkDomainName(podId, ep.Rep)
				if _, ok := hostMap[domain]; ok {
					continue
				}

				hostMap[domain] = ep.Ip
			}
		}
	}

	for domain, ip := range hostMap {
		hosts = append(hosts, domain+":"+ip)
	}

	sort.Strings(hosts)

	return hosts
}

func (inst *BoxInstance) VolumeMountsRefresh() {

	ls := []*inapi.PbVolumeMount{
		{
			Name:      "home",
			MountPath: "/home/action",
			HostDir:   VolPodHomeDir(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId),
			ReadOnly:  false,
		},
		{
			Name:      "opt",
			MountPath: "/opt",
			HostDir:   VolPodPath(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId, "/opt"),
			ReadOnly:  false,
		},
	}

	for _, v := range inst.SpecMounts {

		if strings.HasPrefix(v.Target, "/opt") ||
			strings.HasPrefix(v.Target, "/home/action") {
			continue
		}

		src := filepath.Clean(strings.Replace(v.Source, "{{.POD_SYS_VOL}}",
			VolPodPath(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId, "/"), -1))

		ls, _ = inapi.PbVolumeMountSliceSync(ls, &inapi.PbVolumeMount{
			Name:      "spec-mount-" + strings.ToLower(v.Target),
			MountPath: v.Target,
			HostDir:   src,
			ReadOnly:  false,
		})
	}

	for _, vm := range inst.PackMounts {
		ls, _ = inapi.PbVolumeMountSliceSync(ls, &inapi.PbVolumeMount{
			Name:      "ipm-" + vm.Name,
			HostDir:   vm.HostPath,
			MountPath: InPackMountPath(vm.Name, vm.Version),
			ReadOnly:  true,
		})
	}

	if !inapi.PbVolumeMountSliceEqual(inst.Spec.Mounts, ls) {
		inst.Spec.Mounts = ls
	}
}

func (inst *BoxInstance) BlkioDeviceRefresh() {

	if inst.Replica.VolSys < 1 {
		inst.Replica.VolSys = 1
	} else if inst.Replica.VolSys > blockLimitRange {
		inst.Replica.VolSys = blockLimitRange
	}

	cn := float64(inst.Replica.VolSys - 1)

	inst.BlkioDeviceBps = blockLimitBpsMin + int64(cn*blockLimitBpsRate)
	inst.BlkioDeviceIOps = blockLimitIOpsMin + int64(cn*blockLimitIOpsRate)
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

func (inst *BoxInstance) CpuSets() string {
	cpus := []string{}
	ArrayInt32Sort(inst.SpecCpuSets)
	for _, v := range inst.SpecCpuSets {
		cpus = append(cpus, strconv.Itoa(int(v)))
	}
	return strings.Join(cpus, ",")
}

type SysCpuUsage struct {
	Num   int32 `json:"num"`
	Usage int   `json:"usage"`
}

type VolumeDeviceEntry struct {
	Mountpoint string
	Device     string
}

var box_sets_mu sync.RWMutex

type BoxInstanceSets struct {
	mu         sync.RWMutex
	Items      []*BoxInstance       `json:"items"`
	CpuUsages  []*SysCpuUsage       `json:"cpu_usages"`
	CpuCap     int32                `json:"cpu_cap"`
	VolDevices []*VolumeDeviceEntry `json:"device_map"`
}

func (ls *BoxInstanceSets) Fix() bool {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	chg := false

	if ls.CpuCap != int32(runtime.NumCPU()) {

		ls.CpuUsages = []*SysCpuUsage{}
		ls.CpuCap = int32(runtime.NumCPU())

		for i := int32(0); i < ls.CpuCap; i++ {
			ls.CpuUsages = append(ls.CpuUsages, &SysCpuUsage{
				Num:   i,
				Usage: 0,
			})
		}
	}

	//
	cpuUsages := map[int32]int{}
	for i := int32(0); i < ls.CpuCap; i++ {
		cpuUsages[i] = 0
	}

	for _, inst := range ls.Items {

		if inst.Spec.Resources == nil {
			continue
		}

		for _, v := range inst.SpecCpuSets {
			cpuUsages[v] += int(inst.Spec.Resources.CpuLimit)
		}
	}

	for k, v := range cpuUsages {
		for _, v2 := range ls.CpuUsages {
			if k == v2.Num && v != v2.Usage {
				v2.Usage, chg = v, true
				break
			}
		}
	}

	return chg
}

func (ls *BoxInstanceSets) cpuSort() {

	if ls.CpuCap != int32(runtime.NumCPU()) {
		ls.CpuUsages = []*SysCpuUsage{}
		ls.CpuCap = int32(runtime.NumCPU())
	}

	if len(ls.CpuUsages) < 1 {

		for i := int32(0); i < ls.CpuCap; i++ {
			ls.CpuUsages = append(ls.CpuUsages, &SysCpuUsage{
				Num:   i,
				Usage: 0,
			})
		}
	}

	sort.Slice(ls.CpuUsages, func(i, j int) bool {
		return ls.CpuUsages[i].Usage < ls.CpuUsages[j].Usage
	})
}

func (ls *BoxInstanceSets) SpecCpuSetsDesired(inst *BoxInstance) bool {

	if inst.Spec.Resources != nil {

		ls.cpuSort()

		cpuCores := int32(inst.Spec.Resources.CpuLimit / 10)
		if cpuCores < 1 {
			cpuCores = 1
		} else if cpuCores > ls.CpuCap {
			cpuCores = ls.CpuCap
		}

		for _, v := range inst.SpecCpuSets {
			if v >= int32(len(ls.CpuUsages)) {
				inst.SpecCpuSets = []int32{}
				break
			}
		}

		if int32(len(inst.SpecCpuSets)) != cpuCores {

			inst.SpecCpuSets = []int32{}
			for i, v := range ls.CpuUsages {
				if int32(i) >= cpuCores {
					break
				}
				inst.SpecCpuSets = append(inst.SpecCpuSets, v.Num)
				v.Usage += int(inst.Spec.Resources.CpuLimit)
			}
			ArrayInt32Sort(inst.SpecCpuSets)
			return false
		}
	}

	return true
}

func (ls *BoxInstanceSets) Get(name string) *BoxInstance {

	if name == "" {
		return nil
	}

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	for _, v := range ls.Items {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (ls *BoxInstanceSets) StatusSet(item *BoxInstance) {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	var prev *BoxInstance

	for _, v := range ls.Items {
		if v.Name == item.Name {
			prev = v
			break
		}
	}

	if prev == nil {
		prev = &BoxInstance{
			Name:    item.Name,
			ID:      item.ID,
			PodID:   item.PodID,
			Replica: item.Replica,
			Status:  item.Status,
			Stats:   inapi.NewPbStatsSampleFeed(BoxStatsSampleCycle),
		}
		ls.Items = append(ls.Items, prev)
	} else {
		prev.Status = item.Status
		prev.ID = item.ID
	}
}

func (ls *BoxInstanceSets) Set(item *BoxInstance) {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	ls.SpecCpuSetsDesired(item)

	var prev *BoxInstance

	for _, v := range ls.Items {
		if v.Name == item.Name {
			prev = v
			break
		}
	}

	if prev == nil {
		prev = &BoxInstance{
			Name:         item.Name,
			PodID:        item.PodID,
			PodOpVersion: item.PodOpVersion,
			Spec:         item.Spec,
			Apps:         item.Apps,
			Replica:      item.Replica,
			Stats:        inapi.NewPbStatsSampleFeed(BoxStatsSampleCycle),
			UpUpdated:    item.UpUpdated,
			SpecCpuSets:  item.SpecCpuSets,
		}
		ls.Items = append(ls.Items, prev)
	} else {
		prev.PodOpVersion = item.PodOpVersion
		prev.Spec = item.Spec
		prev.SpecCpuSets = item.SpecCpuSets
		prev.Replica = item.Replica
		prev.Apps = item.Apps
	}
}

func (ls *BoxInstanceSets) Del(name string) {

	box_sets_mu.Lock()
	defer box_sets_mu.Unlock()

	for i, v := range ls.Items {
		if v.Name == name {
			ls.Items = append(ls.Items[:i], ls.Items[i+1:]...)
			return
		}
	}
}

func (ls *BoxInstanceSets) Size() int {

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	return len(ls.Items)
}

func (ls *BoxInstanceSets) Each(fn func(item *BoxInstance)) {

	box_sets_mu.RLock()
	defer box_sets_mu.RUnlock()

	for _, v := range ls.Items {
		fn(v)
	}
}

func (ls *BoxInstanceSets) OpLockNum() int {
	n := 0
	for _, v := range ls.Items {
		if v.opPending {
			n += 1
		}
	}
	return n
}

func (ls *BoxInstanceSets) DeviceGet(mnt string) string {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	for _, v := range ls.VolDevices {
		if strings.HasPrefix(mnt, v.Mountpoint) {
			return v.Device
		}
	}
	return ""
}

func (ls *BoxInstanceSets) DeviceSet(mnt, dev string) string {
	if mnt == "/" || mnt == "" {
		return ""
	}
	for i := len(dev) - 1; i >= 0; i-- {
		if dev[i] < '0' || dev[i] > '9' {
			dev = dev[:i+1]
			break
		}
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, v := range ls.VolDevices {
		if mnt == v.Mountpoint {
			v.Device = dev
			return v.Device
		}
	}
	ls.VolDevices = append(ls.VolDevices, &VolumeDeviceEntry{
		Mountpoint: mnt,
		Device:     dev,
	})
	sort.Slice(ls.VolDevices, func(i, j int) bool {
		return strings.Compare(ls.VolDevices[i].Mountpoint, ls.VolDevices[i].Mountpoint) > 0
	})
	return dev
}

type RsyncModuleItem struct {
	User string `json:"user"`
	Dir  string `json:"dir"`
}

func PodRepNetworkDomainName(podId string, repId uint32) string {
	return fmt.Sprintf("%s.%s", BoxInstanceName(podId, repId),
		config.Config.Zone.NetworkDomainName)
}
