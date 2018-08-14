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

package docker

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/net/portutil"
	"github.com/lessos/lessgo/types"

	drclient "github.com/fsouza/go-dockerclient"

	in_cf "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/ipm"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	mu                 sync.Mutex
	driver             napi.BoxDriver
	timeout            = time.Second * 10
	clientTimeout      = time.Second * 3
	activeNumMax       = 100
	binInstall         = "/usr/bin/install"
	clientUnixSockAddr = "unix:///var/run/docker.sock"
	err                error
)

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
	client       *drclient.Client
	statusSets   chan *napi.BoxInstance
	statsPending bool
	actives      types.ArrayString
	statsSets    chan *napi.BoxInstanceStatsFeed
	sets         types.ArrayString
	createSets   types.KvPairs
}

func (tp *BoxDriver) Name() string {
	return "docker"
}

func (tp *BoxDriver) Start() error {

	tp.mu.Lock()
	defer tp.mu.Unlock()

	if tp.running {
		return nil
	}

	go func() {

		for {

			tp.statusRefresh()

			go tp.statsRefresh()

			time.Sleep(2e9)
		}
	}()

	tp.running = true

	return nil
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

func (tp *BoxDriver) Stop() error {
	return nil
}

func (tp *BoxDriver) statusRefresh() {

	if in_sts.Host.Meta.Id == "" {
		return
	}

	if tp.client == nil {

		for i := 0; i < 3; i++ {

			tp.client, err = drclient.NewClient(clientUnixSockAddr)
			if err == nil {
				tp.client.SetTimeout(clientTimeout)
				break
			}

			time.Sleep(2e9)
			hlog.Printf("warn", "Can not connect to Docker Server, Error: %s", err)
		}

		if tp.client == nil {
			return
		}
	}

	info, err := tp.client.Info()
	if err != nil {
		in_sts.Host.Spec.ExpDockerVersion = ""
		tp.client = nil
		hlog.Printf("warn", "Error on connect to Docker Server, %s", err)
		return
	}
	in_sts.Host.Spec.ExpDockerVersion = info.ServerVersion

	// refresh current statuses
	rsc, err := tp.client.ListContainers(drclient.ListContainersOptions{
		All: true,
	})
	if err != nil {
		hlog.Printf("error", "client.BoxList Error %v", err)
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
			hlog.Printf("warn", "statusSets out of capacity")
			break
		}

		if sts, err := tp.statusEntry(vc.ID); err == nil {
			tp.statusSets <- sts

			if sts.Status.Action == inapi.OpActionRunning {
				key := vc.ID + "," + sts.Name
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

	if !tp.inited {
		tp.inited = true
	}
}

func (tp *BoxDriver) statusEntry(id string) (*napi.BoxInstance, error) {

	boxInspect, err := tp.client.InspectContainer(id)
	if err != nil || boxInspect == nil {
		return nil, fmt.Errorf("Invalid Box ID %s", id)
	}

	pod_id, rep_id, box_name := napi.BoxInstanceNameParse(boxInspect.Config.Hostname)
	if pod_id == "" {
		return nil, fmt.Errorf("Invalid Box Name %s", boxInspect.Config.Hostname)
	}

	tn := uint32(time.Now().Unix())

	inst := &napi.BoxInstance{
		ID:    id,
		Name:  boxInspect.Config.Hostname,
		PodID: pod_id,
		RepId: rep_id,
		Status: inapi.PbPodBoxStatus{
			Name:        box_name,
			Started:     uint32(boxInspect.State.StartedAt.Unix()),
			Updated:     tn,
			ResCpuLimit: boxInspect.HostConfig.CPUShares,
			ResMemLimit: boxInspect.HostConfig.Memory,
			ImageDriver: inapi.PbPodSpecBoxImageDriver_Docker,
			ImageOptions: []*inapi.Label{
				{
					Name:  "docker/image/name",
					Value: boxInspect.Config.Image,
				},
			},
			Command: boxInspect.Config.Cmd,
		},
	}

	//
	for _, cm := range boxInspect.Mounts {
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
		inst.Status.Action = inapi.OpActionRunning
	} else {
		inst.Status.Action = inapi.OpActionStopped
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

	tp.statsPending = false
}

func (tp *BoxDriver) statsEntry(id, name string) (*napi.BoxInstanceStatsFeed, error) {

	var (
		timeout  = 3 * time.Second
		statsBuf = make(chan *drclient.Stats, 2)
	)

	if err := tp.client.Stats(drclient.StatsOptions{
		ID:                id,
		Stats:             statsBuf,
		Stream:            false,
		Timeout:           timeout,
		InactivityTimeout: timeout,
	}); err != nil {
		return nil, err
	}

	stats, ok := <-statsBuf
	if !ok || stats == nil {
		return nil, errors.New("timeout")
	}

	boxStats := &napi.BoxInstanceStatsFeed{
		Name: name,
		Time: uint32(time.Now().Unix()),
	}

	// RAM
	boxStats.Set("ram/us",
		int64(stats.MemoryStats.Usage))
	boxStats.Set("ram/cc",
		int64(stats.MemoryStats.Stats.Cache))

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
	for _, v := range stats.BlkioStats.IOServiceBytesRecursive {
		switch v.Op {
		case "Read":
			fs_rs += int64(v.Value)

		case "Write":
			fs_ws += int64(v.Value)
		}
	}
	for _, v := range stats.BlkioStats.IOServicedRecursive {
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

func (tp *BoxDriver) ActionCommandEntry(inst *napi.BoxInstance) error {

	hlog.Printf("debug", "hostlet/box run %s", inst.Name)

	tp.mu.Lock()
	if tp.sets.Has(inst.Name) {
		tp.mu.Unlock()
		return nil
	}
	tp.sets.Set(inst.Name)
	tp.mu.Unlock()

	defer func(inst_name string) {

		tp.mu.Lock()
		tp.sets.Del(inst_name)
		tp.mu.Unlock()

		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet/box Panic %s %v", inst_name, r)
		}

	}(inst.Name)

	if !tp.inited {
		return errors.New("Box Server Error")
	}

	hlog.Printf("debug", "hostlet/box %s action (%s)",
		inst.Name, strings.Join(inapi.OpActionStrings(inst.Status.Action), ", "))

	if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionDestroy) {

		if inst.Status.Action == inapi.OpActionDestroyed {
			return nil
		}

		if tp.createSets.Get(inst.Name) == nil {
			inst.Status.Action = inapi.OpActionDestroyed
			inst.ID = ""
			hlog.Printf("warn", "hostlet/box %s remove", inst.Name)
			return nil
		}

		//
		if inst.Status.Action == inapi.OpActionRunning {
			if err = tp.client.StopContainer(inst.ID, 10); err != nil {
				inst.Status.Action = inapi.OpActionWarning
			} else {
				inst.Status.Action = inapi.OpActionStopped
				time.Sleep(500e6)
			}
			hlog.Printf("warn", "hostlet/box %s stopped", inst.Name)
		}

		if inst.Status.Action == inapi.OpActionStopped {

			if err = tp.client.RemoveContainer(drclient.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err == nil {
				inst.Status.Action = inapi.OpActionDestroyed
			} else {
				inst.Status.Action = inapi.OpActionWarning
			}

			inst.ID = ""
			hlog.Printf("warn", "hostlet/box removed %s", inst.Name)
		}

		return nil
	}

	// TODO issue
	if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) {
		if err := ipm.Prepare(inst); err != nil {
			hlog.Printf("warn", "hostlet/box ipm_prepare %s", err.Error())
			return err
		}
	}

	if inst.PodOpAction == 0 || inst.Spec.Name == "" {
		hlog.Printf("warn", "hostlet/box Error: No Spec Found BOX:%d:%s",
			inst.PodOpAction, inst.Name)
		return errors.New("No Spec Found")
	}

	var err error

	if inst.ID != "" {

		if inst.SpecDesired() && inst.OpActionDesired() {
			return nil
		}

		// Stop current BOX
		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) {

			if inst.Status.Action == inapi.OpActionRunning {

				if err = tp.client.StopContainer(inst.ID, 10); err != nil {
					// inst.Status.Action = inapi.OpActionWarning
				} else {
					inst.Status.Action = inapi.OpActionStopped
				}

				hlog.Printf("info", "hostlet/box stop %s", inst.Name)
			}

			return nil
		}

		if !inst.SpecDesired() {

			if inst.Status.Action == inapi.OpActionRunning {

				hlog.Printf("info", "hostlet/box Stop %s", inst.Name)

				if err := tp.client.StopContainer(inst.ID, 10); err != nil {
					return err
				}

				inst.Status.Action = inapi.OpActionStopped
			}

			hlog.Printf("info", "hostlet/box Remove %s", inst.Name)

			if err := tp.client.RemoveContainer(drclient.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err != nil {
				inst.Status.Action = inapi.OpActionWarning
				return err
			}

			inst.ID = ""
			time.Sleep(2e8)
		}

	} else {

		if inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStop) {
			// hlog.Printf("info", "hostlet/box Skip Stop+NotExist %s", inst.Name)
			// inst.Status.Action = inapi.OpActionStopped
			return nil
		}
	}

	//
	var (
		dirPodHome = napi.VolPodHomeDir(inst.PodID, inst.RepId)
		initSrc    = in_cf.Prefix + "/bin/ininit"
		initDst    = dirPodHome + "/.sysinner/ininit"
		agentSrc   = in_cf.Prefix + "/bin/inagent"
		agentDst   = dirPodHome + "/.sysinner/inagent"
		bashrcDst  = dirPodHome + "/.bashrc"
		bashpfDst  = dirPodHome + "/.bash_profile"
		bashrcSrc  = in_cf.Prefix + "/misc/bash/bashrc"
		bashpfSrc  = in_cf.Prefix + "/misc/bash/bash_profile"
		expPorts   = map[drclient.Port]struct{}{}
		bindPorts  = map[drclient.Port][]drclient.PortBinding{}
	)

	//
	for _, port := range inst.Ports {

		if port.HostPort == 0 {
			port.HostPort, _ = portutil.Free(30000, 40000)
		}

		portKey := drclient.Port(strconv.Itoa(int(port.BoxPort)) + "/tcp")

		expPorts[portKey] = struct{}{} // TODO TCP,UDP...

		bindPorts[portKey] = append(bindPorts[drclient.Port(strconv.Itoa(int(port.BoxPort)))], drclient.PortBinding{
			HostPort: strconv.Itoa(int(port.HostPort)),
			// HostIP:   in_cf.Config.Host.LanAddr.IP(),
		})
	}

	//
	if inst.ID == "" {

		hlog.Printf("info", "hostlet/box Create %s", inst.Name)

		//
		if err := inutils.FsMakeDir(dirPodHome+"/.sysinner", 2048, 2048, 0750); err != nil {
			hlog.Printf("error", "hostlet/box BOX:%s, FsMakeDir Err:%v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		// hlog.Printf("info", "hostlet/box Create %s, homefs:%s", inst.Name, dirPodHome)

		imgname, ok := inst.Spec.Image.Options.Get("docker/image/name")
		if !ok {
			hlog.Printf("error", "hostlet/box BOX:%s, No Image Name Found", inst.Name)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		boxInspect, err := tp.client.CreateContainer(drclient.CreateContainerOptions{
			Name: inst.Name,
			Config: &drclient.Config{
				Hostname:     inst.Name,
				Memory:       inst.Spec.Resources.MemLimit,
				MemorySwap:   inst.Spec.Resources.MemLimit,
				CPUShares:    inst.Spec.Resources.CpuLimit,
				Cmd:          inst.Spec.Command,
				Image:        imgname.String(),
				ExposedPorts: expPorts,
				Env:          []string{"POD_ID=" + inst.PodID},
				User:         "action",
			},
			HostConfig: &drclient.HostConfig{
				Binds:            inst.VolumeMountsExport(),
				PortBindings:     bindPorts,
				Memory:           inst.Spec.Resources.MemLimit,
				MemorySwap:       inst.Spec.Resources.MemLimit,
				MemorySwappiness: 0,
				CPUShares:        inst.Spec.Resources.CpuLimit,
				Ulimits: []drclient.ULimit{
					{
						Name: "nofile",
						Soft: 50000,
						Hard: 50000,
					},
				},
			},
		})

		if err != nil || boxInspect.ID == "" {
			hlog.Printf("info", "hostlet/box Create %s, Err: %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return errors.New("BoxCreate Error " + err.Error())
		}

		hlog.Printf("info", "hostlet/box Create %s, DONE", inst.Name)

		// TODO
		inst.ID, inst.Status.Action = boxInspect.ID, 0
	}

	if inst.ID != "" &&
		inapi.OpActionAllow(inst.PodOpAction, inapi.OpActionStart) &&
		inst.Status.Action != inapi.OpActionRunning {

		hlog.Printf("info", "hostlet/box Start %s", inst.Name)

		//
		exec.Command(binInstall, "-m", "755", "-g", "root", "-o", "root", initSrc, initDst).Output()
		exec.Command(binInstall, "-m", "755", "-g", "root", "-o", "root", agentSrc, agentDst).Output()
		exec.Command(binInstall, bashrcSrc, bashrcDst).Output()
		exec.Command(binInstall, bashpfSrc, bashpfDst).Output()

		err = tp.client.StartContainer(inst.ID, nil)

		if err != nil {
			hlog.Printf("info", "hostlet/box Start %s, Error %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		hlog.Printf("info", "hostlet/box Start %s, DONE", inst.Name)

		inst.Status.Action = inapi.OpActionRunning

		time.Sleep(1e9)
		// tp.docker_status_watch_entry(inst.ID)
	} else {
		hlog.Printf("info", "hostlet/box Start %s, SKIP", inst.Name)
	}

	return nil
}
