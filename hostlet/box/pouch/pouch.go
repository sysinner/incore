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

	drclient_types "github.com/alibaba/pouch/apis/types"
	drclient "github.com/alibaba/pouch/client"

	in_cf "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/ipm"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

var (
	driver             napi.BoxDriver
	mu                 sync.Mutex
	clientUnixSockAddr = "unix:///var/run/pouchd.sock"
	err                error
	timeParsePouchFmt  = time.RFC3339Nano
	activeNumMax       = 100
	binInstall         = "/usr/bin/install"
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
	mu         sync.Mutex
	mmu        *locker.HashPool
	inited     bool
	running    bool
	client     drclient.CommonAPIClient
	statusSets chan *napi.BoxInstance
	actives    types.ArrayString
	statsSets  chan *napi.BoxInstanceStatsFeed
	sets       types.ArrayString
	createSets types.KvPairs
}

func (tp *BoxDriver) Name() string {
	return "pouch"
}

func (tp *BoxDriver) Start() error {

	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.inited = false

	if !tp.running {

		go func() {

			for {

				tp.statusRefresh()

				time.Sleep(2e9)
			}
		}()

		tp.running = true
	}

	return nil
}

func (tp *BoxDriver) statusRefresh() {

	if in_sts.Host.Meta.Id == "" {
		return
	}

	if len(tp.statusSets) > activeNumMax {
		return
	}

	if tp.client == nil {

		for i := 0; i < 3; i++ {

			tp.client, err = drclient.NewAPIClient(clientUnixSockAddr,
				drclient.TLSConfig{})
			if err == nil {
				break
			}

			time.Sleep(2e9)
			hlog.Printf("warn", "Can not connect to Pouch Server, Error: %s", err)
		}

		if tp.client == nil {
			return
		}
	}

	info, err := tp.client.SystemInfo(context.Background())
	if err != nil {
		in_sts.Host.Spec.ExpPouchVersion = ""
		tp.client = nil
		hlog.Printf("warn", "Error on connect to Pouch Server, %s", err)
		return
	}
	in_sts.Host.Spec.ExpPouchVersion = info.ServerVersion

	rsc, err := tp.client.ContainerList(context.Background(), drclient_types.ContainerListOptions{
		All: true,
	})
	if err != nil {
		hlog.Printf("error", "drclient.ContainerList Error %v", err)
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

	if !tp.inited {
		time.Sleep(2e9)
		tp.inited = true
	}
}

func (tp *BoxDriver) entryStatus(id string) (*napi.BoxInstance, error) {

	box_pouch, err := tp.client.ContainerGet(context.Background(), id)
	if err != nil || box_pouch == nil {
		return nil, fmt.Errorf("Invalid Box ID %s", id)
	}

	pod_id, rep_id, box_name := napi.BoxInstanceNameParse(box_pouch.Name)
	if pod_id == "" {
		return nil, fmt.Errorf("Invalid Box Name %s", box_pouch.Name)
	}

	tn := uint32(time.Now().Unix())

	inst := &napi.BoxInstance{
		ID:    id,
		Name:  box_pouch.Name,
		PodID: pod_id,
		RepId: rep_id,
		Status: inapi.PbPodBoxStatus{
			Name:        box_name,
			Started:     uint32(timeParsePouch(box_pouch.State.StartedAt).Unix()),
			Updated:     tn,
			ResCpuLimit: box_pouch.HostConfig.CPUQuota / 1e3,
			ResMemLimit: box_pouch.HostConfig.Memory,
			ImageDriver: inapi.PbPodSpecBoxImageDriver_Pouch,
			ImageOptions: []*inapi.Label{
				{
					Name:  "image/id",
					Value: box_pouch.Config.Image,
				},
			},
			Command: box_pouch.Config.Cmd,
		},
	}

	//
	for _, cm := range box_pouch.Mounts {

		if !strings.HasPrefix(cm.Destination, "/home/action") &&
			!strings.HasPrefix(cm.Destination, "/usr/sysinner/") &&
			!strings.HasPrefix(cm.Destination, "/dev/shm/sysinner/nsz") {
			continue
		}

		inst.Status.Mounts = append(inst.Status.Mounts, &inapi.PbVolumeMount{
			MountPath: cm.Destination,
			HostDir:   cm.Source,
			ReadOnly:  !cm.RW,
		})
	}

	// TODO
	if len(box_pouch.HostConfig.PortBindings) > 0 {

		for box_pouchPortKey, box_pouchPorts := range box_pouch.HostConfig.PortBindings {

			if len(box_pouchPorts) < 1 {
				continue
			}

			ps := strings.Split(string(box_pouchPortKey), "/")
			if len(ps) != 2 {
				continue
			}

			var (
				boxPort, _  = strconv.Atoi(ps[0])
				hostPort, _ = strconv.Atoi(box_pouchPorts[0].HostPort)
			)

			inst.Status.Ports = append(inst.Status.Ports, &inapi.PbServicePort{
				BoxPort:  uint32(boxPort),
				HostPort: uint32(hostPort),
				// Protocol: inapi.ProtocolTCP, //
				// HostIP:   conf.Config.HostAddr,
			})
		}
	}

	if box_pouch.State.Running {
		inst.Status.Action = inapi.OpActionRunning
	} else {
		inst.Status.Action = inapi.OpActionStopped
	}

	return inst, nil
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
			if err = tp.client.ContainerStop(context.Background(), inst.ID, "10"); err != nil {
				inst.Status.Action = inapi.OpActionWarning
			} else {
				inst.Status.Action = inapi.OpActionStopped
				time.Sleep(500e6)
			}
			hlog.Printf("warn", "hostlet/box %s stopped", inst.Name)
		}

		if inst.Status.Action == inapi.OpActionStopped {

			if err = tp.client.ContainerRemove(context.Background(), inst.ID, &drclient_types.ContainerRemoveOptions{
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

				// start := time.Now()
				if err = tp.client.ContainerStop(context.Background(), inst.ID, "10"); err != nil {
					inst.Status.Action = inapi.OpActionWarning
				}
				// fmt.Println("stop in", time.Since(start))

				hlog.Printf("info", "hostlet/box stop %s", inst.Name)
			}

			return err
		}

		if !inst.SpecDesired() {

			if inst.Status.Action == inapi.OpActionRunning {

				hlog.Printf("info", "hostlet/box Stop %s", inst.Name)

				if err := tp.client.ContainerStop(context.Background(), inst.ID, "10"); err != nil {
					return err
				}

				inst.Status.Action = inapi.OpActionStopped
			}

			hlog.Printf("info", "hostlet/box Remove %s", inst.Name)

			if err := tp.client.ContainerRemove(context.Background(), inst.ID, &drclient_types.ContainerRemoveOptions{
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
		expPorts   = map[string]interface{}{}
		bindPorts  = map[string][]drclient_types.PortBinding{}
	)

	//
	for _, port := range inst.Ports {

		if port.HostPort == 0 {
			port.HostPort, _ = portutil.Free(30000, 40000)
		}

		boxPort := strconv.Itoa(int(port.BoxPort)) + "/tcp"

		expPorts[boxPort] = struct{}{} // TODO TCP,UDP...

		bindPorts[boxPort] = append(bindPorts[boxPort], drclient_types.PortBinding{
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

		imageName := inst.Spec.Image.Ref.Id
		if imageName != "" && strings.IndexByte(imageName, ':') < 0 {
			imageName = inapi.BoxImageRepoDefault + ":" + inst.Spec.Image.Ref.Id
		}

		if imageName == "" {
			hlog.Printf("error", "hostlet/box BOX:%s, No Image Name Found", inst.Name)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		bpConfig := drclient_types.ContainerConfig{
			Cmd:          inst.Spec.Command,
			Image:        imageName,
			ExposedPorts: expPorts,
			Env:          []string{"POD_ID=" + inst.PodID},
			User:         "action",
			WorkingDir:   "/home/action",
		}
		bpHostConfig := &drclient_types.HostConfig{
			EnableLxcfs:  in_cf.Config.LxcFsEnable,
			GroupAdd:     []string{"action"},
			NetworkMode:  "bridge",
			Binds:        inst.VolumeMountsExport(),
			PortBindings: bindPorts,
			Resources: drclient_types.Resources{
				Memory:     inst.Spec.Resources.MemLimit,
				MemorySwap: inst.Spec.Resources.MemLimit,
				CPUPeriod:  1000000,
				CPUQuota:   inst.Spec.Resources.CpuLimit * 1e3,
				Ulimits: []*drclient_types.Ulimit{
					{
						Name: "nofile",
						Soft: 10000,
						Hard: 10000,
					},
				},
			},
		}
		bpNetworkingConfig := &drclient_types.NetworkingConfig{
			//
		}

		box_pouch, err := tp.client.ContainerCreate(
			context.Background(),
			bpConfig,
			bpHostConfig,
			bpNetworkingConfig,
			inst.Name,
		)

		if err != nil || box_pouch.ID == "" {
			hlog.Printf("info", "hostlet/box Create %s, Err: %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return errors.New("BoxCreate Error " + err.Error())
		}

		hlog.Printf("info", "hostlet/box Create %s, DONE", inst.Name)

		// TODO
		inst.ID, inst.Status.Action = box_pouch.ID, 0
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

		err = tp.client.ContainerStart(context.Background(), inst.ID, drclient_types.ContainerStartOptions{})

		if err != nil {
			hlog.Printf("info", "hostlet/box Start %s, Error %v", inst.Name, err)
			inst.Status.Action = inapi.OpActionWarning
			return err
		}

		hlog.Printf("info", "hostlet/box Start %s, DONE", inst.Name)

		inst.Status.Action = inapi.OpActionRunning

		time.Sleep(1e9)
		// tp.box_status_watch_entry(inst.ID)
	} else {
		hlog.Printf("info", "hostlet/box Start %s, SKIP", inst.Name)
	}

	return nil
}

func (tp *BoxDriver) Stop() error {
	return nil
}
