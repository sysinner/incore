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

	drvClient "github.com/fsouza/go-dockerclient"

	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/ipm"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
	insta "github.com/sysinner/incore/status"
)

var (
	mu                 sync.Mutex
	driver             *BoxDriver
	timeout            = time.Second * 10
	clientTimeout      = time.Second * 10
	activeNumMax       = 100
	binInstall         = "/usr/bin/install"
	clientUnixSockAddr = "unix:///var/run/docker.sock"
	lxcfsBins          = [][]string{
		{"bin/innerstack-lxcfs", "/var/lib/innerstack-lxcfs/proc/"},
		{"/usr/bin/lxcfs", "/var/lib/lxcfs/proc/"},
	}
	lxcfsMounts = []string{
		"cpuinfo",
		"diskstats",
		"meminfo",
		"stat",
		"swaps",
		"uptime",
	}
	err                     error
	cfgStorageOptSizeEnable = true
)

func NewDriver() (napi.BoxDriver, error) {

	mu.Lock()
	defer mu.Unlock()

	if driver == nil {

		vols := []string{}

		for _, vp := range lxcfsBins {

			binpath := vp[0]
			if binpath[0] != '/' {
				binpath = incfg.Prefix + "/" + binpath
			}

			if _, err := exec.Command("pidof", binpath).Output(); err != nil {
				continue
			}

			for _, v := range lxcfsMounts {
				vols = append(vols, fmt.Sprintf("%s:%s:ro", vp[1]+v, "/proc/"+v))
				hlog.Printf("info", "lxcfs bin %s, proc %s", vp[0], vp[1])
			}

			break
		}

		driver = &BoxDriver{
			inited:     false,
			mmu:        locker.NewHashPool(runtime.NumCPU()),
			statusSets: make(chan *napi.BoxInstance, activeNumMax+10),
			statsSets:  make(chan *napi.BoxInstanceStatsFeed, activeNumMax+10),
			lxcfsVols:  vols,
		}
	}

	return driver, nil
}

const (
	dockerNetworkVPCName = "invpc_docker"
)

type BoxDriver struct {
	mu           sync.Mutex
	mmu          *locker.HashPool
	inited       bool
	running      bool
	client       *drvClient.Client
	statusSets   chan *napi.BoxInstance
	statsPending bool
	actives      types.ArrayString
	statsSets    chan *napi.BoxInstanceStatsFeed
	sets         types.ArrayString
	createSets   types.KvPairs
	lxcfsVols    []string
	imageSets    types.ArrayString
	vpcSubnet    string
	vpcNetworID  string
}

func (tp *BoxDriver) Name() string {
	return "docker"
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

func (tp *BoxDriver) statusRefresh() {

	if insta.Host.Meta.Id == "" {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if tp.client == nil {

		for i := 0; i < 3; i++ {

			tp.client, err = drvClient.NewClient(clientUnixSockAddr)
			if err == nil {
				tp.client.SetTimeout(clientTimeout)
				break
			}

			hlog.Printf("warn", "hostlet/docker/connect error %s", err.Error())

			time.Sleep(2e9)
			if len(tp.sets) > 0 {
				hlog.Printf("warn", "hostlet/status/refresh, Can not connect to Docker Server %s", err)
			}
		}

		if tp.client == nil {
			return
		}
	}

	info, err := tp.client.Info()
	if err != nil {
		insta.Host.Spec.ExpDockerVersion = ""
		tp.client = nil
		if len(tp.sets) > 0 {
			hlog.Printf("warn", "hostlet/status/refresh, failed on connect to Docker %s", err)
		}
		return
	}
	insta.Host.Spec.ExpDockerVersion = info.ServerVersion

	// refresh current network status
	if true {
		// ListNetworks() ([]Network, error)
		nets, err := tp.client.ListNetworks()
		if err != nil {
			hlog.Printf("warn", "hostlet/status/refresh, network/list err %v", err)
			tp.inited = false
			return
		}

		for _, v := range nets {

			if v.Name != dockerNetworkVPCName {
				continue
			}

			for _, v2 := range v.IPAM.Config {
				tp.vpcSubnet = v2.Subnet
				tp.vpcNetworID = v.ID
				break
			}

			if tp.vpcSubnet != incfg.Config.Host.NetworkVpcInstance {
				tp.client.RemoveNetwork(v.ID)
				time.Sleep(1e9)
			}

			break
		}

		if tp.vpcSubnet != incfg.Config.Host.NetworkVpcInstance {
			if br, err := tp.client.CreateNetwork(drvClient.CreateNetworkOptions{
				Name:   dockerNetworkVPCName,
				Driver: "bridge",
				IPAM: &drvClient.IPAMOptions{
					Config: []drvClient.IPAMConfig{
						{
							Subnet: incfg.Config.Host.NetworkVpcInstance,
						},
					},
				},
				CheckDuplicate: true,
			}); err == nil {
				tp.vpcSubnet = incfg.Config.Host.NetworkVpcInstance
				tp.vpcNetworID = br.ID
			}
		}
	}

	// refresh current container statuses
	rsc, err := tp.client.ListContainers(drvClient.ListContainersOptions{
		All: true,
	})
	if err != nil {
		hlog.Printf("warn", "hostlet/status/refresh, container/list err %v", err)
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
			hlog.Printf("warn", "hostlet/status/refresh, container/list/status, out of capacity %d", activeNumMax)
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

	// refresh current images
	if !tp.inited {
		tp.imageListRefresh()
	}

	if !tp.inited {
		tp.inited = true
	}
}

func (tp *BoxDriver) imageListRefresh() error {

	rsi, err := tp.client.ListImages(drvClient.ListImagesOptions{
		All: false,
	})
	if err == nil {
		for _, v := range rsi {
			for _, v2 := range v.RepoTags {
				tp.imageSets.Set(v2)
				if !tp.inited {
					hlog.Printf("debug", "hostlet/box images tag %s", v2)
				}
			}
		}
		if !tp.inited {
			hlog.Printf("info", "hostlet/box load %d images", len(tp.imageSets))
		}
	}
	return err
}

func (tp *BoxDriver) statusEntry(id string) (*napi.BoxInstance, error) {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	boxInspect, err := tp.client.InspectContainer(id)
	if err != nil || boxInspect == nil {
		return nil, fmt.Errorf("Invalid Box ID %s", id)
	}

	podId, repId := napi.BoxInstanceNameParse(boxInspect.Config.Hostname)
	if podId == "" {
		return nil, fmt.Errorf("Invalid Box Name %s", boxInspect.Config.Hostname)
	}

	tn := uint32(time.Now().Unix())

	cpuSets := []int32{}
	if sets := strings.Split(boxInspect.HostConfig.CPUSetCPUs, ","); len(sets) > 0 {
		for _, v := range sets {
			if n, _ := strconv.Atoi(v); n >= 0 && n < 256 {
				cpuSets = append(cpuSets, int32(n))
			}
		}
	}

	inst := &napi.BoxInstance{
		ID:    id,
		Name:  boxInspect.Config.Hostname,
		PodID: podId,
		Replica: inapi.PodOperateReplica{
			RepId: repId,
		},
		Status: inapi.PbPodBoxStatus{
			Started:     uint32(boxInspect.State.StartedAt.Unix()),
			Updated:     tn,
			ResCpuLimit: int32(boxInspect.HostConfig.CPUQuota / 1e5),
			ResMemLimit: int32(boxInspect.HostConfig.Memory / inapi.ByteMB),
			ImageDriver: inapi.PbPodSpecBoxImageDriver_Docker,
			ImageOptions: []*inapi.Label{
				{
					Name:  "image/id",
					Value: boxInspect.Config.Image,
				},
			},
			Command:     boxInspect.Config.Cmd,
			CpuSets:     cpuSets,
			NetworkMode: inapi.AppSpecExpDeployNetworkModeBridge,
		},
	}

	if boxInspect.HostConfig.NetworkMode == "host" {
		inst.Status.NetworkMode = inapi.AppSpecExpDeployNetworkModeHost
	} else if boxInspect.NetworkSettings != nil &&
		boxInspect.NetworkSettings.Networks != nil {
		if n, ok := boxInspect.NetworkSettings.Networks[dockerNetworkVPCName]; ok {
			inst.Status.NetworkIpv4 = n.IPAddress
		}
	}

	//
	for _, cm := range boxInspect.Mounts {

		/**
		if !strings.HasPrefix(cm.Destination, "/home/action") &&
			!strings.HasPrefix(cm.Destination, "/opt") &&
			// !strings.HasPrefix(cm.Destination, "/etc/hosts") &&
			!strings.HasPrefix(cm.Destination, "/usr/sysinner/") {
			continue
		}
		*/
		if strings.HasPrefix(cm.Destination, "/proc/") {
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
			hlog.Printf("warn", "hostlet/status/refresh, container/list/status, out of capacity %d", activeNumMax)
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

	var (
		statsTimeout = 3 * time.Second
		statsBuf     = make(chan *drvClient.Stats, 2)
	)

	if err := tp.client.Stats(drvClient.StatsOptions{
		ID:                id,
		Stats:             statsBuf,
		Stream:            false,
		Timeout:           statsTimeout,
		InactivityTimeout: statsTimeout,
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
		// hlog.Printf("warn", "hostlet/box ipm_prepare %s", err.Error())
		return err
	}

	// hlog.Printf("info", "hostlet/box start %s", inst.Name)

	if inst.ID != "" {

		if inst.SpecDesired() && inst.OpActionDesired() {
			return nil
		}

		if !inst.SpecDesired() {

			if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

				hlog.Printf("info", "hostlet box %s, stop", inst.Name)

				if err := tp.client.StopContainer(inst.ID, 10); err == nil ||
					strings.Contains(err.Error(), "No such container") ||
					strings.Contains(err.Error(), "Container not running") {
					inst.StatusActionSet(inapi.OpActionStopped)
					time.Sleep(200e6)
				} else {
					return err
				}
			}

			// hlog.Printf("info", "hostlet/box Remove %s", inst.Name)

			if err := tp.client.RemoveContainer(drvClient.RemoveContainerOptions{
				ID:    inst.ID,
				Force: true,
			}); err != nil &&
				!strings.Contains(err.Error(), "No such container") {
				inst.StatusActionSet(inapi.OpActionWarning)
				hlog.Printf("info", "hostlet box %s, remove err %s", inst.Name, err.Error())
				return err
			}

			hlog.Printf("info", "hostlet box %s, remove", inst.Name)

			inst.ID = ""
			time.Sleep(2e8)
		}
	}

	//
	if inst.ID == "" {

		//
		var (
			expPorts  = map[drvClient.Port]struct{}{}
			bindPorts = map[drvClient.Port][]drvClient.PortBinding{}
		)

		//
		for _, port := range inst.Replica.Ports {

			if port.HostPort == 0 {
				port.HostPort, _ = portutil.Free(30000, 40000)
			}

			portKey := drvClient.Port(strconv.Itoa(int(port.BoxPort)) + "/tcp")
			if strings.HasSuffix(port.Name, "/auto") {
				portKey = drvClient.Port(strconv.Itoa(int(port.HostPort)) + "/tcp")
			}

			expPorts[portKey] = struct{}{} // TODO TCP,UDP...

			bindPorts[portKey] = append(bindPorts[drvClient.Port(strconv.Itoa(int(port.BoxPort)))], drvClient.PortBinding{
				HostPort: strconv.Itoa(int(port.HostPort)),
				HostIP:   "0.0.0.0", //   incfg.Config.Host.LanAddr.IP(),
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

		var (
			netMode    = "bridge"
			extHosts   = inst.ExtHosts(false)
			dnsServers = []string{}
		)

		if inst.Replica.VpcIpv4 != "" {
			if tp.vpcSubnet == "" {
				return errors.New("docker network subnet not ready, waiting ...")
			}
			dnsServers = []string{
				inapi.HostNodeAddress(incfg.Config.Host.LanAddr).IP(),
			}
		}

		if inst.Apps.NetworkModeHost() {
			netMode = "host"
		}

		hlog.Printf("info", "hostlet/box Create %s, hosts %s, image %s",
			inst.Name, strings.Join(extHosts, ","), imageName)

		storOpt := map[string]string{}
		if cfgStorageOptSizeEnable {
			storOpt["size"] = "10G"
		}

		boxCreateOptions := drvClient.CreateContainerOptions{
			Name: inst.Name,
			Config: &drvClient.Config{
				Hostname:     inst.Name,
				Cmd:          inst.Spec.Command,
				Image:        imageName,
				ExposedPorts: expPorts,
				Env: []string{
					"POD_ID=" + inst.PodID,
					fmt.Sprintf("REP_ID=%d", inst.Replica.RepId),
				},
				User: "action",
				DNS:  dnsServers,
			},
			HostConfig: &drvClient.HostConfig{
				NetworkMode:  netMode,
				ExtraHosts:   extHosts,
				PortBindings: bindPorts,
				DNS:          dnsServers,
				Binds:        append(inst.VolumeMountsExport(), tp.lxcfsVols...),
				Memory:       int64(inst.Spec.Resources.MemLimit) * inapi.ByteMB,
				MemorySwap:   int64(inst.Spec.Resources.MemLimit) * inapi.ByteMB,
				// MemorySwappiness: 0,
				CPUPeriod:  1000000,
				CPUQuota:   int64(inst.Spec.Resources.CpuLimit) * 1e5,
				CPUSetCPUs: inst.CpuSets(),
				Ulimits: []drvClient.ULimit{
					{
						Name: "nofile",
						Soft: 10000,
						Hard: 10000,
					},
				},
				StorageOpt:    storOpt,
				RestartPolicy: drvClient.RestartUnlessStopped(),
			},
		}

		if netMode == "bridge" && inst.Replica.VpcIpv4 != "" {
			boxCreateOptions.NetworkingConfig = &drvClient.NetworkingConfig{
				EndpointsConfig: map[string]*drvClient.EndpointConfig{
					dockerNetworkVPCName: {
						IPAMConfig: &drvClient.EndpointIPAMConfig{
							IPv4Address: inst.Replica.VpcIpv4,
						},
					},
				},
			}
		}

		if !strings.HasPrefix(imageName, "sysinner/innerstack-") {
			boxCreateOptions.Config.User = "root"
		}

		if runtime.GOOS != "linux" {
			boxCreateOptions.HostConfig.CPUSetCPUs = ""
			boxCreateOptions.Config.User = "root"
		}

		boxInspect, err := tp.client.CreateContainer(boxCreateOptions)

		if err != nil && !strings.Contains(err.Error(), "container already exists") {
			// --storage-opt is supported only for overlay over xfs with 'pquota' mount option
			if strings.Contains(err.Error(), "storage-opt") {
				cfgStorageOptSizeEnable = false
			}
			if strings.Contains(err.Error(), "no such image") {
				tp.imageSets.Del(imageName)
			}

			hlog.Printf("info", "hostlet/box Create %s, Err: %v", inst.Name, err)
			inst.StatusActionSet(inapi.OpActionWarning)
			return errors.New("BoxCreate Warning " + err.Error())
		}

		if boxInspect != nil && boxInspect.ID != "" {
			inst.ID = boxInspect.ID
			hlog.Printf("info", "hostlet/box Create %s OK", inst.Name)
			inst.SetupHosts = extHosts
			inst.StatusActionSet(0)
		}
	}

	hlog.Printf("info", "box pod %s, rep %d, opAction %s, status %s",
		inst.PodID, inst.Replica.RepId,
		strings.Join(inapi.OpActionStrings(inst.Replica.Action), ","),
		strings.Join(inapi.OpActionStrings(inst.Status.Action), ","),
	)

	if inst.ID != "" &&
		inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) &&
		!inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

		// hlog.Printf("info", "hostlet/box Start %s", inst.Name)

		if err := tp.client.StartContainer(inst.ID, nil); err != nil {

			hlog.Printf("info", "hostlet/box Start %s, Error %v", inst.Name, err)

			if strings.Contains(err.Error(), "OCI runtime create failed") ||
				strings.Contains(err.Error(), "storage-opt") {

				if err = tp.client.RemoveContainer(drvClient.RemoveContainerOptions{
					ID:    inst.ID,
					Force: true,
				}); err == nil {
					inst.ID = ""
					hlog.Printf("warn", "hostlet/box %s : remove and re-create", inst.Name)
				}
				time.Sleep(1e9)
			} else if strings.Contains(err.Error(), "No such container") ||
				strings.Contains(err.Error(), "no such file or directory") {
				inst.ID = ""
			}
			inst.StatusActionSet(inapi.OpActionWarning)
			return err
		}

		hlog.Printf("info", "hostlet/box Start %s OK", inst.Name)

		inst.StatusActionSet(inapi.OpActionRunning)

		time.Sleep(100e6)
		// tp.docker_status_watch_entry(inst.ID)
	} else {
		// hlog.Printf("info", "hostlet/box Start %s, SKIP", inst.Name)
		// inapi.ObjPrint(inst.Name, inst)
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

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

	if inst.ID == "" {
		return nil
	}

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {

		if err := tp.client.StopContainer(inst.ID, 5); err == nil ||
			strings.Contains(err.Error(), "No such container") ||
			strings.Contains(err.Error(), "Container not running") {
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

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "hostlet panic %v", r)
		}
	}()

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
		if err = tp.client.StopContainer(inst.ID, 10); err == nil ||
			strings.Contains(err.Error(), "No such container") ||
			strings.Contains(err.Error(), "Container not running") {
			inst.StatusActionSet(inapi.OpActionStopped)
			time.Sleep(500e6)
		} else {
			inst.StatusActionSet(inapi.OpActionWarning)
		}
		hlog.Printf("warn", "hostlet/box %s stopped", inst.Name)
	}

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionStopped) {

		if err = tp.client.RemoveContainer(drvClient.RemoveContainerOptions{
			ID:    inst.ID,
			Force: true,
		}); err == nil ||
			strings.Contains(err.Error(), "No such container") {
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

	err := tp.client.PullImage(drvClient.PullImageOptions{
		Repository: imageName,
	}, drvClient.AuthConfiguration{})
	if err != nil {
		hlog.Printf("warn", "hostlet/box %s, pull image %s, error %s", inst.Name, imageName, err.Error())
	} else {
		tp.imageSets.Set(imageName)
		hlog.Printf("info", "hostlet/box %s, pull image %s, ok", inst.Name, imageName)
	}

	return err
}
