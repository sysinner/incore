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

package hostlet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"golang.org/x/net/context"

	ps_cpu "github.com/shirou/gopsutil/cpu"
	ps_disk "github.com/shirou/gopsutil/disk"
	ps_mem "github.com/shirou/gopsutil/mem"
	ps_net "github.com/shirou/gopsutil/net"

	"github.com/sysinner/incore/config"
	// "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	"github.com/sysinner/incore/rpcsrv"
	"github.com/sysinner/incore/status"
)

var (
	statsPodRepNames = []string{
		"ram/us", "ram/cc",
		"net/rs", "net/ws",
		"cpu/us",
		"fs/rn", "fs/rs", "fs/wn", "fs/ws",
	}
	statsHostNames = []string{
		"ram/us", "ram/cc",
		"net/rs", "net/ws",
		"cpu/sys", "cpu/user",
		"fs/sp/rn", "fs/sp/rs", "fs/sp/wn", "fs/sp/ws",
	}
)

func zoneMasterSync() error {

	//
	if len(config.Config.Masters) == 0 {
		return errors.New("No MasterList.Items Found")
	}

	zms, err := msgZoneMasterHostStatusSync()
	if err != nil {
		return err
	}

	if zms.ExpPods != nil {

		for _, v := range zms.ExpPods {

			var pod inapi.PodRep

			if err := json.Decode([]byte(v), &pod); err != nil {
				hlog.Printf("warn", "hostlet/zm/sync %s", err.Error())
				continue
			}

			if pod.Meta.ID == "" ||
				pod.Replica.Node != status.Host.Meta.Id {
				continue
			}

			if err := podRepCtrlSet(&pod); err != nil {
				nstatus.PodRepOpLogs.LogSet(
					pod.RepKey(), pod.Operate.Version,
					napi.NsOpLogHostletRepSync, inapi.PbOpLogError,
					fmt.Sprintf("pod %s, err %s", pod.Meta.ID, err.Error()),
				)
			} else {
				nstatus.PodRepOpLogs.LogSet(
					pod.RepKey(), pod.Operate.Version,
					napi.NsOpLogHostletRepSync, inapi.PbOpLogOK,
					fmt.Sprintf("pod %s, OK", pod.Meta.ID),
				)
			}
		}
	}

	// fmt.Println(zms)
	if zms.Masters != nil {
		if chg := status.LocalZoneMasterList.SyncList(zms.Masters); chg {
			ms := inapi.HostNodeAddresses{}
			for _, v := range zms.Masters.Items {
				addr := inapi.HostNodeAddress(v.Addr)
				if addr.Valid() {
					ms = append(ms, inapi.HostNodeAddress(addr))
				}
			}
			if len(ms) > 0 && !config.Config.Masters.Equal(ms) {
				config.Config.Masters = ms
				config.Config.Sync()
				hlog.Printf("info", "hostlet/config/masters refreshed")
			}
		}
	}

	if zms.ExpBoxRemoves != nil {
		sets := types.ArrayString(zms.ExpBoxRemoves)
		for _, v := range sets {
			nstatus.PodRepRemoves.Set(v)
		}
		dels := []string{}
		for _, v := range nstatus.PodRepRemoves {
			if !sets.Has(v) {
				dels = append(dels, v)
			}
		}
		for _, v := range dels {
			nstatus.PodRepRemoves.Del(v)
		}
	} else if len(nstatus.PodRepRemoves) > 0 {
		nstatus.PodRepRemoves.Clean()
	}

	if zms.ExpBoxStops != nil {
		sets := types.ArrayString(zms.ExpBoxStops)
		for _, v := range sets {
			nstatus.PodRepStops.Set(v)
		}
		dels := []string{}
		for _, v := range nstatus.PodRepStops {
			if !sets.Has(v) {
				dels = append(dels, v)
			}
		}
		for _, v := range dels {
			nstatus.PodRepStops.Del(v)
		}
	} else if len(nstatus.PodRepStops) > 0 {
		nstatus.PodRepStops.Clean()
	}

	if len(zms.ZoneInpackServiceUrl) > 10 && zms.ZoneInpackServiceUrl != config.Config.InpackServiceUrl {
		config.Config.InpackServiceUrl = zms.ZoneInpackServiceUrl
		config.Config.Sync()
	}

	if err := podVolQuotaRefresh(); err != nil {
		hlog.Printf("error", "failed to refresh quota projects: %s", err.Error())
	}

	return nil
}

var (
	hostSyncVolLasted int64 = 0
)

func msgZoneMasterHostStatusSync() (*inapi.ResHostBound, error) {

	//
	addr := status.LocalZoneMasterList.LeaderAddr()
	if addr == "" {
		if len(config.Config.Masters) > 0 {
			addr = string(config.Config.Masters[0])
		}
		if addr == "" {
			return nil, errors.New("No MasterList.LeaderAddr Found")
		}
	}
	// hlog.Printf("info", "No MasterList.LeaderAddr Addr: %s", addr)

	//
	conn, err := rpcsrv.ClientConn(addr)
	if err != nil {
		hlog.Printf("error", "No MasterList.LeaderAddr Found: %s", addr)
		return nil, err
	}

	// host/meta
	if status.Host.Meta == nil {
		status.Host.Meta = &inapi.ObjectMeta{
			Id: status.Host.Meta.Id,
		}
	}

	// host/spec
	if status.Host.Spec == nil {

		status.Host.Spec = &inapi.ResHostSpec{
			PeerLanAddr: string(config.Config.Host.LanAddr),
			PeerWanAddr: string(config.Config.Host.WanAddr),
		}
	}

	//
	if status.Host.Spec.Platform == nil {

		os, arch, _ := inutils.ResSysHostEnvDistArch()

		status.Host.Spec.Platform = &inapi.ResPlatform{
			Os:     os,
			Arch:   arch,
			Kernel: inutils.ResSysHostKernel(),
		}
	}

	//
	if status.Host.Spec.Capacity == nil {

		vm, _ := ps_mem.VirtualMemory()

		status.Host.Spec.Capacity = &inapi.ResHostResource{
			Cpu: uint64(runtime.NumCPU()) * 1000,
			Mem: vm.Total,
		}
	}

	tn := time.Now().Unix()

	if len(status.Host.Status.Volumes) == 0 ||
		(hostSyncVolLasted+600) < tn {

		var (
			devs, _ = ps_disk.Partitions(false)
			vols    = []*inapi.ResHostVolume{}
		)

		sort.Slice(devs, func(i, j int) bool {
			if strings.Compare(devs[i].Device+devs[i].Mountpoint, devs[j].Device+devs[j].Device) < 0 {
				return true
			}
			return false
		})

		ars := types.ArrayString{}
		for _, dev := range devs {

			if ars.Has(dev.Device) {
				continue
			}
			ars.Set(dev.Device)

			if !strings.HasPrefix(dev.Device, "/dev/") ||
				strings.HasPrefix(dev.Mountpoint, "/boot") ||
				strings.Contains(dev.Mountpoint, "/devicemapper/mnt/") {
				continue
			}

			if st, err := ps_disk.Usage(dev.Mountpoint); err == nil {
				vols = append(vols, &inapi.ResHostVolume{
					Name:  dev.Mountpoint,
					Total: st.Total,
					Used:  st.Used,
				})
			}
		}

		if len(vols) > 0 {

			sort.Slice(vols, func(i, j int) bool {
				if strings.Compare(vols[i].Name, vols[j].Name) < 0 {
					return true
				}
				return false
			})

			status.Host.Status.Volumes = vols
		}

		hostSyncVolLasted = tn
	}

	if stats := hostStatsFeed(); stats != nil {
		status.Host.Status.Stats = stats
	}

	// Pod Rep Status
	status.Host.Prs = []*inapi.PbPodRepStatus{}
	ctrDels := []string{}
	nstatus.PodRepActives.Each(func(podRep *inapi.PodRep) {

		instName := napi.BoxInstanceName(podRep.Meta.ID, podRep.Replica.RepId)

		if inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionDestroy) &&
			nstatus.PodRepRemoves.Has(instName) {
			return
		}

		if inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionStop) &&
			nstatus.PodRepStops.Has(instName) {
			return
		}

		repStatus := &inapi.PbPodRepStatus{
			PodId:  podRep.Meta.ID,
			RepId:  podRep.Replica.RepId,
			OpLog:  nstatus.PodRepOpLogs.Get(podRep.RepKey()),
			Action: 0,
		}

		// TODO
		if repStatus.OpLog == nil {
			hlog.Printf("warn", "No OpLog Found %s", podRep.RepKey())
			return
		}

		//

		boxInst := nstatus.BoxActives.Get(instName)
		if boxInst == nil {
			repStatus.Action = inapi.OpActionPending
		} else {

			repStatus.Action = boxInst.Status.Action
			repStatus.Started = boxInst.Status.Started
			repStatus.Updated = boxInst.Status.Updated
			repStatus.Ports = boxInst.Status.Ports

			// fmt.Println("repStatus", strings.Join(inapi.OpActionStrings(repStatus.Action), "|"))

			if boxInst.Stats != nil {

				//
				var (
					feed            = inapi.NewPbStatsSampleFeed(napi.BoxStatsLogCycle)
					ec_time  uint32 = 0
					ec_value int64  = 0
				)
				for _, name := range statsPodRepNames {
					if ec_time, ec_value = boxInst.Stats.Extract(name, napi.BoxStatsLogCycle, ec_time); ec_value >= 0 {
						feed.SampleSync(name, ec_time, ec_value, false)
					}
				}

				if len(feed.Items) > 0 {
					repStatus.Stats = feed
				}
			}
		}

		if inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionDestroy) &&
			inapi.OpActionAllow(repStatus.Action, inapi.OpActionDestroyed) {

			ctrDels = append(ctrDels, podRep.RepKey())

			dir := napi.PodVolSysDir(podRep.Meta.ID, podRep.Replica.RepId)
			if _, err := os.Stat(dir); err == nil {
				dir2 := napi.PodVolSysDirArch(podRep.Meta.ID, podRep.Replica.RepId)
				if err = os.Rename(dir, dir2); err != nil {
					hlog.Printf("error", "pod %s, rep %d, archive vol-sys err %s",
						podRep.Meta.ID, podRep.Replica.RepId, err.Error())
					return
				}
			}

		}

		// hlog.Printf("debug", "PodRep %s Phase %s", podRep.RepKey(), repStatus.Phase)

		// js, _ := json.Encode(repStatus, "  ")
		// fmt.Println(string(js))

		if proj := quotaConfig.Fetch(podRep.RepKey()); proj != nil {
			repStatus.Volumes = []*inapi.PbVolumeStatus{
				{
					MountPath: "/home/action",
					Used:      proj.Used,
				},
			}
		}

		if inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			repStatus.Action = repStatus.Action | inapi.OpActionUnbound
		}

		status.Host.Prs = append(status.Host.Prs, repStatus)

		var boxOpLog inapi.PbOpLogSets
		fpath := fmt.Sprintf(napi.AgentBoxStatus, config.Config.PodHomeDir, podRep.RepKey())
		if err := json.DecodeFile(fpath, &boxOpLog); err == nil {
			if boxOpLog.Version >= repStatus.OpLog.Version {
				for _, vlog := range boxOpLog.Items {
					repStatus.OpLog.LogSetEntry(vlog)
				}
			}
		}
	})

	for _, v := range ctrDels {
		nstatus.PodRepActives.Del(v)
	}

	zms, err := inapi.NewApiZoneMasterClient(conn).HostStatusSync(
		context.Background(), &status.Host,
	)
	if err == nil {
		//
	}

	return zms, err
}

var (
	hostStats = inapi.NewPbStatsSampleFeed(napi.BoxStatsSampleCycle)
)

func hostStatsFeed() *inapi.PbStatsSampleFeed {

	timo := uint32(time.Now().Unix())

	// RAM
	vm, _ := ps_mem.VirtualMemory()
	hostStats.SampleSync("ram/us", timo, int64(vm.Used), false)
	hostStats.SampleSync("ram/cc", timo, int64(vm.Cached), false)

	// Networks
	nio, _ := ps_net.IOCounters(false)
	if len(nio) > 0 {
		hostStats.SampleSync("net/rs", timo, int64(nio[0].BytesRecv), false)
		hostStats.SampleSync("net/ws", timo, int64(nio[0].BytesSent), false)
	}

	// CPU
	cio, _ := ps_cpu.Times(false)
	if len(cio) > 0 {
		hostStats.SampleSync("cpu/sys", timo, int64(cio[0].User*float64(1e9)), false)
		hostStats.SampleSync("cpu/user", timo, int64(cio[0].System*float64(1e9)), false)
	}

	// Storage IO
	devs, _ := ps_disk.Partitions(false)
	if dev_name := diskDevName(devs, config.Config.PodHomeDir); dev_name != "" {
		if diom, err := ps_disk.IOCounters(dev_name); err == nil {
			if dio, ok := diom[dev_name]; ok {
				hostStats.SampleSync("fs/sp/rn", timo, int64(dio.ReadCount), false)
				hostStats.SampleSync("fs/sp/rs", timo, int64(dio.ReadBytes), false)
				hostStats.SampleSync("fs/sp/wn", timo, int64(dio.WriteCount), false)
				hostStats.SampleSync("fs/sp/ws", timo, int64(dio.WriteBytes), false)
			}
		}
	}

	//
	var (
		feed            = inapi.NewPbStatsSampleFeed(napi.BoxStatsLogCycle)
		ec_time  uint32 = 0
		ec_value int64  = 0
	)
	for _, name := range statsHostNames {
		if ec_time, ec_value = hostStats.Extract(name, napi.BoxStatsLogCycle, ec_time); ec_value >= 0 {
			feed.SampleSync(name, ec_time, ec_value, false)
		}
	}

	if len(feed.Items) > 0 {
		return feed
	}

	return nil
}

func diskDevName(pls []ps_disk.PartitionStat, path string) string {

	path = filepath.Clean(path)

	for {

		for _, v := range pls {
			if path == v.Mountpoint {
				if strings.HasPrefix(v.Device, "/dev/") {
					return v.Device[5:]
				}
				return ""
			}
		}

		if i := strings.LastIndex(path, "/"); i > 0 {
			path = path[:i]
		} else if len(path) > 1 && path[0] == '/' {
			path = "/"
		} else {
			break
		}
	}

	return ""
}
