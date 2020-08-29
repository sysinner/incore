// Copyright 2018 Eryx <evorui аt gmаil dοt cοm>, All rights reserved.
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

package pouch

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/net/portutil"
	"github.com/lessos/lessgo/types"

	drvClientFilters "github.com/alibaba/pouch/apis/filters"
	drvClientTypes "github.com/alibaba/pouch/apis/types"
	drvClient "github.com/alibaba/pouch/client"

	inCfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/ipm"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
	inSts "github.com/sysinner/incore/status"
)

var (
	driver             napi.BoxDriver
	mu                 sync.Mutex
	clientUnixSockAddr = "unix:///var/run/pouchd.sock"
	timeParsePouchFmt  = time.RFC3339Nano
	activeNumMax       = 100
	binInstall         = "/usr/bin/install"
	err                error
)

func timeParsePouch(tn string) time.Time {
	t, err := time.Parse(timeParsePouchFmt, tn)
	if err == nil {
		return t
	}
	return time.Now()
}

func NewDriver() (napi.BoxDriver, error) {

	mu.Lock()
	defer mu.Unlock()

	if driver == nil {
		driver = &BoxDriver{
			inited:     false,
			mmu:        locker.NewHashPool(runtime.NumCPU()),
			statusSets: make(chan *napi.BoxInstance, activeNumMax+10),
			statsSets:  make(chan *napi.BoxInstanceStatsFeed, activeNumMax+10),
		}
	}

	return driver, nil
}

type BoxDriver struct {
	mu           sync.Mutex
	mmu          *locker.HashPool
	inited       bool
	running      bool
	client       drvClient.CommonAPIClient
	statusSets   chan *napi.BoxInstance
	actives      types.ArrayString
	statsPending bool
	statsSets    chan *napi.BoxInstanceStatsFeed
	sets         types.ArrayString
	createSets   types.KvPairs
	imageSets    types.ArrayString
}

func (tp *BoxDriver) Name() string {
	return "pouch"
}

func (tp *BoxDriver) Start() error {

	tp.mu.Lock()
	defer tp.mu.Unlock()

	if !tp.running {

		go func() {

			for {

				tp.statusRefresh()

				go tp.statsRefresh()

				time.Sleep(3e9)
			}
		}()

		tp.running = true
	}

	return nil
}

func (tp *BoxDriver) Stop() error {
	return nil
}

func (tp *BoxDriver) statusRefresh() {

	if inSts.Host.Meta.Id == "" {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if tp.client == nil {

		for i := 0; i < 3; i++ {

			tp.client, err = drvClient.NewAPIClient(clientUnixSockAddr,
				drvClient.TLSConfig{})
			if err == nil {
				// hlog.Printf("info", "hostlet/status/refresh, connect to Pouch Server OK")
				break
			}

			time.Sleep(2e9)
			if len(tp.sets) > 0 {
				hlog.Printf("warn", "hostlet/status/refresh, Can not connect to Pouch Server %s", err.Error())
			}
		}

		if tp.client == nil {
			return
		}
	}

	info, err := tp.client.SystemInfo(context.Background())
	if err != nil {
		inSts.Host.Spec.ExpPouchVersion = ""
		tp.client = nil
		if len(tp.sets) > 0 {
			hlog.Printf("warn", "Error on connect to Pouch Server, %s", err.Error())
		}
		return
	}
	inSts.Host.Spec.ExpPouchVersion = info.ServerVersion

	rsc, err := tp.client.ContainerList(context.Background(), drvClientTypes.ContainerListOptions{
		All: true,
	})
	if err != nil {
		hlog.Printf("error", "drvClient.ContainerList Error %v", err)
		tp.inited = false
		return
	}

	actives := types.ArrayString{}
	creates := types.ArrayString{}

	for _, vc := range rsc {

		if len(vc.Names) < 1 || len(vc.Names[0]) < 8 {
			continue
		}

		name := strings.Trim(vc.Names[0], "/")

		tp.createSets.Set(name, vc.ID)
		creates.Set(name)

		if len(tp.statusSets) > activeNumMax {
			break
		}

		if sts, err := tp.entryStatus(vc.ID); err == nil {

			tp.statusSets <- sts

			if sts.Status.Action == inapi.OpActionRunning {
				key := vc.ID + "," + name
				tp.actives.Set(key)
				actives.Set(key)
			}

		} else {
			continue
		}
	}

	for _, v := range tp.actives {
		if !actives.Has(v) {
			tp.actives.Del(v)
		}
	}

	for _, v := range tp.createSets {
		if !creates.Has(v.Key) {
			tp.createSets.Del(v.Key)
		}
	}

	// refresh current images
	if !tp.inited {
		if rsi, err := tp.client.ImageList(context.Background(),
			drvClientFilters.NewArgs()); err == nil {
			for _, v := range rsi {
				for _, v2 := range v.RepoTags {
					tp.imageSets.Set(v2)
					hlog.Printf("info", "hostlet/box images tag %s", v2)
				}
			}
			hlog.Printf("info", "hostlet/box images %d", len(tp.imageSets))
		}
	}

	if !tp.inited {
		time.Sleep(2e9)
		tp.inited = true
	}
}

func (tp *BoxDriver) entryStatus(id string) (*napi.BoxInstance, error) {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	boxInspect, err := tp.client.ContainerGet(context.Background(), id)
	if err != nil || boxInspect == nil {
		return nil, fmt.Errorf("Invalid Box ID %s", id)
	}

	podId, repId := napi.BoxInstanceNameParse(boxInspect.Name)
	if podId == "" {
		return nil, fmt.Errorf("Invalid Box Name %s", boxInspect.Name)
	}

	tn := uint32(time.Now().Unix())

	cpuSets := []int32{}
	if sets := strings.Split(boxInspect.HostConfig.CpusetCpus, ","); len(sets) > 0 {
		for _, v := range sets {
			if n, _ := strconv.Atoi(v); n >= 0 && n < 256 {
				cpuSets = append(cpuSets, int32(n))
			}
		}
	}

	inst := &napi.BoxInstance{
		ID:    id,
		Name:  boxInspect.Name,
		PodID: podId,
		Replica: inapi.PodOperateReplica{
			RepId: repId,
		},
		Status: inapi.PbPodBoxStatus{
			Started:     uint32(timeParsePouch(boxInspect.State.StartedAt).Unix()),
			Updated:     tn,
			ResCpuLimit: int32(boxInspect.HostConfig.CPUQuota / 1e5),
			ResMemLimit: int32(boxInspect.HostConfig.Memory / inapi.ByteMB),
			ImageDriver: inapi.PbPodSpecBoxImageDriver_Pouch,
			ImageOptions: []*inapi.Label{
				{
					Name:  "image/id",
					Value: boxInspect.Config.Image,
				},
			},
			Command: boxInspect.Config.Cmd,
			CpuSets: cpuSets,
		},
	}

	//
	for _, cm := range boxInspect.Mounts {

		if !strings.HasPrefix(cm.Destination, "/home/action") &&
			!strings.HasPrefix(cm.Destination, "/opt") &&
			// !strings.HasPrefix(cm.Destination, "/etc/hosts") &&
			!strings.HasPrefix(cm.Destination, "/usr/sysinner/") {
			continue
		}

		inst.Status.Mounts = append(inst.Status.Mounts, &inapi.PbVolumeMount{
			MountPath: cm.Destination,
			HostDir:   cm.Source,
			ReadOnly:  !cm.RW,
		})
	}

	// TODO
	if len(boxInspect.HostConfig.PortBindings) > 0 {

		for boxInspectPortKey, boxInspectPorts := range boxInspect.HostConfig.PortBindings {

			if len(boxInspectPorts) < 1 {
				continue
			}

			ps := strings.Split(string(boxInspectPortKey), "/")
			if len(ps) != 2 {
				continue
			}

			var (
				boxPort, _  = strconv.Atoi(ps[0])
				hostPort, _ = strconv.Atoi(boxInspectPorts[0].HostPort)
			)

			inst.Status.Ports = append(inst.Status.Ports, &inapi.PbServicePort{
				BoxPort:  uint32(boxPort),
				HostPort: uint32(hostPort),
				// Protocol: inapi.ProtocolTCP, //
				// HostIP:   conf.Config.HostAddr,
			})
		}
	}

	if boxInspect.State.Running {
		inst.StatusActionSet(inapi.OpActionRunning)
	} else {
		inst.StatusActionSet(inapi.OpActionStopped)
	}

	return inst, nil
}

func (tp *BoxDriver) statsRefresh() {

	if !tp.inited {
		return
	}

	tp.mu.Lock()

	if tp.statsPending {
		tp.mu.Unlock()
		return
	}

	tp.statsPending = true
	tp.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}

		tp.statsPending = false
	}()

	for _, key := range tp.actives {

		if len(tp.statsSets) > activeNumMax {
			hlog.Printf("warn", "statsSets out of capacity")
			break
		}

		n := strings.IndexByte(key, ',')
		id, name := key[:n], key[n+1:]

		if sts, err := tp.statsEntry(id, name); err == nil {
			tp.statsSets <- sts
		} else {
			hlog.Printf("error", "box.Stats %s error %s", id, err.Error())
		}
	}
}

func (tp *BoxDriver) statsEntry(id, name string) (*napi.BoxInstanceStatsFeed, error) {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	statsBuf, err := tp.client.ContainerStats(context.Background(), name, false)
	if err != nil {
		return nil, err
	}
	var stats drvClientTypes.ContainerStats
	if bs, err := ioutil.ReadAll(statsBuf); err != nil {
		return nil, err
	} else {
		if err := json.Decode(bs, &stats); err != nil {
			return nil, err
		}
	}

	if stats.CPUStats == nil || stats.MemoryStats == nil {
		return nil, errors.New("timeout")
	}

	boxStats := &napi.BoxInstanceStatsFeed{
		Name: name,
		Time: uint32(time.Now().Unix()),
	}

	// RAM
	boxStats.Set("ram/us",
		int64(stats.MemoryStats.Usage))
	if v, ok := stats.MemoryStats.Stats["cache"]; ok {
		boxStats.Set("ram/cc", int64(v))
	}

	// Networks
	net_io_rs := int64(0)
	net_io_ws := int64(0)
	for _, v := range stats.Networks {
		net_io_rs += int64(v.RxBytes)
		net_io_ws += int64(v.TxBytes)
	}
	boxStats.Set("net/rs", net_io_rs)
	boxStats.Set("net/ws", net_io_ws)

	// CPU
	boxStats.Set("cpu/us",
		int64(stats.CPUStats.CPUUsage.TotalUsage))

	// Storage IO
	fs_rn := int64(0)
	fs_rs := int64(0)
	fs_wn := int64(0)
	fs_ws := int64(0)
	for _, v := range stats.BlkioStats.IoServiceBytesRecursive {
		switch v.Op {
		case "Read":
			fs_rs += int64(v.Value)

		case "Write":
			fs_ws += int64(v.Value)
		}
	}
	for _, v := range stats.BlkioStats.IoServicedRecursive {
		switch v.Op {
		case "Read":
			fs_rn += int64(v.Value)

		case "Write":
			fs_wn += int64(v.Value)
		}
	}
	boxStats.Set("fs/rn", fs_rn)
	boxStats.Set("fs/rs", fs_rs)
	boxStats.Set("fs/wn", fs_wn)
	boxStats.Set("fs/ws", fs_ws)

	return boxStats, nil
}

func (tp *BoxDriver) StatusEntry() *napi.BoxInstance {
	if len(tp.statusSets) < 1 {
		return nil
	}
	return <-tp.statusSets
}

func (tp *BoxDriver) StatsEntry() *napi.BoxInstanceStatsFeed {
	if len(tp.statsSets) < 1 {
		return nil
	}
	return <-tp.statsSets
}

func (tp *BoxDriver) BoxCreate(inst *napi.BoxInstance) error {
	return nil
}

func (tp *BoxDriver) BoxStart(inst *napi.BoxInstance) error {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) {
		return nil
	}

	if !tp.inited {
		return errors.New("Box Server Init Error")
	}

	if inst.Spec.Name == "" {
		hlog.Printf("warn", "hostlet/box Error: No Spec Found BOX:%d:%s",
			inst.Replica.Action, inst.Name)
		// inapi.ObjPrint(inst.Name, inst.Spec)
		return errors.New("No Spec Found")
	}

	if err := ipm.Prepare(inst); err != nil {
		hlog.Printf("warn", "hostlet/box ipm_prepare %s", err.Error())
		return err
	}

	if inst.ID != "" {

		if inst.SpecDesired() && inst.OpActionDesired() {
			return nil
		}

		if !inst.SpecDesired() {

			if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

				hlog.Printf("info", "hostlet box %s, start", inst.Name)

				if err = tp.client.ContainerStop(context.Background(), inst.ID, "10"); err == nil ||
					strings.Contains(err.Error(), "not found") ||
					strings.Contains(err.Error(), "Container not running") {
					inst.StatusActionSet(inapi.OpActionStopped)
					time.Sleep(2e8)
				} else {
					return err
				}
			}

			// hlog.Printf("info", "hostlet/box Remove %s", inst.Name)

			if err := tp.client.ContainerRemove(context.Background(), inst.ID, &drvClientTypes.ContainerRemoveOptions{
				Force: true,
			}); err != nil &&
				!strings.Contains(err.Error(), "not found") {
				inst.StatusActionSet(inapi.OpActionWarning)
				hlog.Printf("info", "hostlet box %s, remove err %s", inst.Name, err.Error())
				return err
			}

			inst.ID = ""
			time.Sleep(2e8)
		}
	}

	//
	if inst.ID == "" {

		//
		var (
			expPorts  = map[string]interface{}{}
			bindPorts = map[string][]drvClientTypes.PortBinding{}
		)

		//
		for _, port := range inst.Replica.Ports {

			if port.HostPort == 0 {
				port.HostPort, _ = portutil.Free(30000, 40000)
			}

			boxPort := strconv.Itoa(int(port.BoxPort)) + "/tcp"

			expPorts[boxPort] = struct{}{} // TODO TCP,UDP...

			bindPorts[boxPort] = append(bindPorts[boxPort], drvClientTypes.PortBinding{
				HostPort: strconv.Itoa(int(port.HostPort)),
				// HostIP:   inCfg.Config.Host.LanAddr.IP(),
			})
		}

		// hlog.Printf("info", "hostlet/box Create %s", inst.Name)

		// hlog.Printf("info", "hostlet/box Create %s, homefs:%s", inst.Name, dirPodHome)

		imageName := inst.Spec.Image.Ref.Id
		if imageName != "" && strings.IndexByte(imageName, ':') < 0 {
			imageName = inapi.BoxImageRepoDefault + ":" + inst.Spec.Image.Ref.Id
		}

		if imageName == "" {
			hlog.Printf("error", "hostlet/box BOX:%s, No Image Name Found", inst.Name)
			inst.StatusActionSet(inapi.OpActionWarning)
			return err
		}

		bpConfig := drvClientTypes.ContainerConfig{
			Cmd:          inst.Spec.Command,
			Image:        imageName,
			ExposedPorts: expPorts,
			Env:          []string{"POD_ID=" + inst.PodID},
			User:         "action",
			WorkingDir:   "/home/action",
			DiskQuota: map[string]string{
				"size": "10G",
			},
		}
		bpHostConfig := &drvClientTypes.HostConfig{
			EnableLxcfs:  inCfg.Config.LxcFsEnable,
			NetworkMode:  "bridge",
			PortBindings: bindPorts,
			Binds:        inst.VolumeMountsExport(),
			Resources: drvClientTypes.Resources{
				Memory:     int64(inst.Spec.Resources.MemLimit) * inapi.ByteMB,
				MemorySwap: int64(inst.Spec.Resources.MemLimit) * inapi.ByteMB,
				CPUPeriod:  1000000,
				CPUQuota:   int64(inst.Spec.Resources.CpuLimit) * 1e5,
				CpusetCpus: inst.CpuSets(),
				Ulimits: []*drvClientTypes.Ulimit{
					{
						Name: "nofile",
						Soft: 30000,
						Hard: 30000,
					},
				},
			},
			StorageOpt: map[string]string{
				"size": "10G",
			},
			RestartPolicy: &drvClientTypes.RestartPolicy{
				Name: "unless-stopped",
			},
		}
		bpNetworkingConfig := &drvClientTypes.NetworkingConfig{
			//
		}

		boxInspect, err := tp.client.ContainerCreate(
			context.Background(),
			bpConfig,
			bpHostConfig,
			bpNetworkingConfig,
			inst.Name,
		)

		if err != nil && !strings.Contains(err.Error(), "already existed") {
			hlog.Printf("info", "hostlet/box Create %s, Err: %v", inst.Name, err)
			inst.StatusActionSet(inapi.OpActionWarning)
			return errors.New("BoxCreate Error " + err.Error())
			//
		}

		if boxInspect != nil && boxInspect.ID != "" {
			inst.ID = boxInspect.ID
			hlog.Printf("info", "hostlet/box Create %s OK", inst.Name)
			inst.StatusActionSet(0)
		}
	}

	if inst.ID != "" &&
		inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) &&
		!inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

		// hlog.Printf("info", "hostlet/box Start %s", inst.Name)

		if err := tp.client.ContainerStart(context.Background(), inst.ID, drvClientTypes.ContainerStartOptions{}); err != nil {

			hlog.Printf("error", "hostlet/box Start %s, Error %v", inst.Name, err)

			if strings.Contains(err.Error(), "not found") {
				inst.ID = ""
			} else if strings.Contains(err.Error(), "failed to create container") {

				if err := tp.client.ContainerRemove(context.Background(), inst.ID, &drvClientTypes.ContainerRemoveOptions{
					Force: true,
				}); err == nil {
					inst.ID = ""
				}
			}

			inst.StatusActionSet(inapi.OpActionWarning)
			return err
		}

		hlog.Printf("info", "hostlet/box Start %s OK", inst.Name)

		inst.StatusActionSet(inapi.OpActionRunning)

		time.Sleep(1e9)
		// tp.box_status_watch_entry(inst.ID)
	} else {
		// hlog.Printf("info", "hostlet/box Start %s, SKIP", inst.Name)
	}

	return nil
}

func (tp *BoxDriver) BoxStop(inst *napi.BoxInstance) error {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStop) {
		return nil
	}

	if !tp.inited {
		return errors.New("Box Server Init Error")
	}

	if inst.ID == "" {
		return nil
	}

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

		if err := tp.client.ContainerStop(context.Background(), inst.ID, "5"); err == nil ||
			strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "not running") {
			inst.StatusActionSet(inapi.OpActionStopped)
			hlog.Printf("info", "hostlet box %s, stop OK", inst.Name)
		} else {
			hlog.Printf("info", "hostlet box %s, stop err %s",
				inst.Name, err.Error())
		}
	}

	return nil
}

func (tp *BoxDriver) BoxRemove(inst *napi.BoxInstance) error {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionDestroy) {
		return nil
	}

	if !tp.inited {
		return errors.New("Box Server Init Error")
	}

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionDestroyed) {
		return nil
	}

	if tp.createSets.Get(inst.Name) == nil {
		inst.StatusActionSet(inapi.OpActionDestroyed)
		inst.ID = ""
		hlog.Printf("debug", "hostlet/box %s remove", inst.Name)
		return nil
	}

	//
	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

		if err = tp.client.ContainerStop(context.Background(), inst.ID, "10"); err == nil ||
			strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "not running") {
			inst.StatusActionSet(inapi.OpActionStopped)
			time.Sleep(500e6)
		} else {
			inst.StatusActionSet(inapi.OpActionWarning)
		}
		hlog.Printf("warn", "hostlet/box %s stopped", inst.Name)
	}

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionStopped) {

		if err := tp.client.ContainerRemove(context.Background(), inst.ID, &drvClientTypes.ContainerRemoveOptions{
			Force: true,
		}); err == nil ||
			strings.Contains(err.Error(), "not found") {
			inst.StatusActionSet(inapi.OpActionDestroyed)
			inst.ID = ""
			hlog.Printf("warn", "hostlet/box removed %s", inst.Name)
		} else {
			inst.StatusActionSet(inapi.OpActionWarning)
		}
	}

	return nil
}

func (tp *BoxDriver) BoxExist(inst *napi.BoxInstance) (bool, error) {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if !tp.inited {
		return false, errors.New("un init")
	}

	if tp.createSets.Get(inst.Name) != nil {
		return true, nil
	}
	return false, nil
}

func (tp *BoxDriver) ImageSetup(inst *napi.BoxInstance) error {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) {
		return nil
	}

	imageName := inst.Spec.Image.Ref.Id
	if imageName != "" && strings.IndexByte(imageName, ':') < 0 {
		imageName = inapi.BoxImageRepoDefault + ":" + inst.Spec.Image.Ref.Id
	}

	if tp.imageSets.Has(imageName) {
		return nil
	}

	return errors.New("noimp")
}
