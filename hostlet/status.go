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
	"runtime"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lynkdb/iomix/skv"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/hostlet/podrunner"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	"github.com/sysinner/incore/rpcsrv"
	"github.com/sysinner/incore/status"
)

const (
	inagent_box_status = "%s/%s/home/action/.sysinner/box_status.json"
)

func status_tracker() {

	//
	if len(status.LocalZoneMasterList.Items) == 0 {

		var zms inapi.ResZoneMasterList
		if rs := data.LocalDB.PvGet(inapi.NsLocalZoneMasterList()); rs.OK() {

			if err := rs.Decode(&zms); err == nil {

				if synced := status.LocalZoneMasterList.SyncList(zms); synced {

					cms := []inapi.HostNodeAddress{}
					for _, v := range status.LocalZoneMasterList.Items {
						cms = append(cms, inapi.HostNodeAddress(v.Addr))
					}

					if len(cms) > 0 {
						config.Config.Masters = cms
						config.Config.Sync()
					}
				}
			}
		}
	}

	//
	if len(status.LocalZoneMasterList.Items) == 0 {
		hlog.Printf("warn", "No MasterList.Items Found")
		return
	}

	zms, err := msgZoneMasterHostStatusSync()
	if err != nil {
		hlog.Printf("warn", "No MasterList.LeaderAddr Found %s", err.Error())
		return
	}

	// fmt.Println(zms)
	if status.LocalZoneMasterList.SyncList(*zms) {
		hlog.Printf("warn", "CHANGED LZML")
		// TODO
	}

	sync_nsz()
}

var (
	sync_nsz_lasts = map[string]uint64{}
)

func sync_nsz() {

	os.MkdirAll("/dev/shm/sysinner/nsz", 0755)

	rs := data.HiMaster.PvScan(inapi.NsZonePodServiceMap(""), "", "", 10000)

	rs.KvEach(func(v *skv.ResultEntry) int {

		var nsz inapi.NsPodServiceMap
		if err := v.Decode(&nsz); err != nil {
			return 0
		}

		last, ok := sync_nsz_lasts[string(v.Key)]
		if !ok || nsz.Updated > last {
			json.EncodeToFile(nsz, "/dev/shm/sysinner/nsz/"+string(v.Key), "")
			sync_nsz_lasts[string(v.Key)] = nsz.Updated
		}

		return 0
	})
}

func msgZoneMasterHostStatusSync() (*inapi.ResZoneMasterList, error) {

	//
	addr := status.LocalZoneMasterList.LeaderAddr()
	if addr == nil {
		return nil, errors.New("No MasterList.LeaderAddr Found")
	}

	//
	conn, err := rpcsrv.ClientConn(*addr)
	if err != nil {
		hlog.Printf("error", "No MasterList.LeaderAddr Found")
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

	// status.Host.Spec.SecretKey = config.Config.Host.SecretKey

	if status.Host.Spec.Platform == nil {

		os, arch, _ := inutils.ResSysHostEnvDistArch()

		status.Host.Spec.Platform = &inapi.ResPlatform{
			Os:     os,
			Arch:   arch,
			Kernel: inutils.ResSysHostKernel(),
		}
	}

	if status.Host.Spec.Capacity == nil {

		vm, _ := mem.VirtualMemory()

		status.Host.Spec.Capacity = &inapi.ResHostResource{
			Cpu: uint64(runtime.NumCPU()) * 1000,
			Mem: vm.Total,
		}
	}

	status.Host.Prs = []*inapi.PbPodRepStatus{}

	// fmt.Println("pod", len(podrunner.PodRepActives))
	// fmt.Println("box", len(podrunner.BoxActives))

	// Pod Rep Status
	podrunner.PodRepActives.Each(func(pod *inapi.Pod) {

		if pod.Operate.Replica == nil {
			return
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStop|inapi.OpActionStopped) ||
			inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			return
		}

		pod_status := &inapi.PbPodRepStatus{
			Id:    pod.Meta.ID,
			Rep:   uint32(pod.Operate.Replica.Id),
			OpLog: podrunner.PodRepOpLogs.Get(pod.OpRepKey()),
		}

		if pod_status.OpLog == nil {
			hlog.Printf("warn", "No OpLog Found %s", pod.OpRepKey())
			return
		}

		action := uint32(0)

		//
		for _, bspec := range pod.Spec.Boxes {

			inst_name := podrunner.BoxInstanceName(pod.Meta.ID, pod.Operate.Replica, bspec.Name)

			box_inst := podrunner.BoxActives.Get(inst_name)
			if box_inst == nil {
				action = inapi.OpActionPending
				continue
			}

			if action == 0 {
				action = box_inst.Status.Action
			}

			if action != box_inst.Status.Action {
				action = inapi.OpActionPending
			}

			pod_status.Boxes = append(pod_status.Boxes, &box_inst.Status)
		}

		pod_status.Action = action
		// hlog.Printf("debug", "PodRep %s Phase %s", pod.OpRepKey(), pod_status.Phase)

		// js, _ := json.Encode(pod_status, "  ")
		// fmt.Println(string(js))

		status.Host.Prs = append(status.Host.Prs, pod_status)

		var box_oplog inapi.PbOpLogSets
		fpath := fmt.Sprintf(inagent_box_status, config.Config.PodHomeDir, pod.OpRepKey())
		if err := json.DecodeFile(fpath, &box_oplog); err == nil {
			if box_oplog.Version >= pod_status.OpLog.Version {
				for _, vlog := range box_oplog.Items {
					pod_status.OpLog.LogSetEntry(vlog)
				}
			}
		}
	})

	return inapi.NewApiZoneMasterClient(conn).HostStatusSync(
		context.Background(), &status.Host,
	)
}
