// Copyright 2015 Authors, All rights reserved.
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
	"os"
	"runtime"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lynkdb/iomix/skv"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/net/context"

	"github.com/lessos/loscore/config"
	"github.com/lessos/loscore/data"
	"github.com/lessos/loscore/losapi"
	"github.com/lessos/loscore/losutils"
	"github.com/lessos/loscore/rpcsrv"
	"github.com/lessos/loscore/status"
)

func status_tracker() {

	//
	if len(status.LocalZoneMasterList.Items) == 0 {

		var zms losapi.ResZoneMasterList
		if rs := data.LocalDB.PvGet(losapi.NsLocalZoneMasterList()); rs.OK() {

			if err := rs.Decode(&zms); err == nil {

				if synced := status.LocalZoneMasterList.SyncList(zms); synced {

					cms := []losapi.HostNodeAddress{}
					for _, v := range status.LocalZoneMasterList.Items {
						cms = append(cms, losapi.HostNodeAddress(v.Addr))
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

	os.MkdirAll("/dev/shm/los/nsz", 0755)

	rs := data.HiMaster.PvScan(losapi.NsZonePodServiceMap(""), "", "", 10000)

	rs.KvEach(func(v *skv.ResultEntry) int {

		var nsz losapi.NsPodServiceMap
		if err := v.Decode(&nsz); err != nil {
			return 0
		}

		last, ok := sync_nsz_lasts[string(v.Key)]
		if !ok || nsz.Updated > last {
			json.EncodeToFile(nsz, "/dev/shm/los/nsz/"+string(v.Key), "")
			sync_nsz_lasts[string(v.Key)] = nsz.Updated
		}

		return 0
	})
}

func msgZoneMasterHostStatusSync() (*losapi.ResZoneMasterList, error) {

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
		status.Host.Meta = &losapi.ObjectMeta{
			Id: status.Host.Meta.Id,
		}
	}

	// host/spec
	if status.Host.Spec == nil {

		status.Host.Spec = &losapi.ResHostSpec{
			PeerLanAddr: string(config.Config.Host.LanAddr),
			PeerWanAddr: string(config.Config.Host.WanAddr),
		}
	}

	// status.Host.Spec.SecretKey = config.Config.Host.SecretKey

	if status.Host.Spec.Platform == nil {

		os, arch, _ := losutils.ResSysHostEnvDistArch()

		status.Host.Spec.Platform = &losapi.ResPlatform{
			Os:     os,
			Arch:   arch,
			Kernel: losutils.ResSysHostKernel(),
		}
	}

	if status.Host.Spec.Capacity == nil {

		vm, _ := mem.VirtualMemory()

		status.Host.Spec.Capacity = &losapi.ResHostResource{
			Cpu:    uint64(runtime.NumCPU()) * 1000,
			Memory: vm.Total,
		}
	}

	return losapi.NewApiZoneMasterClient(conn).HostStatusSync(
		context.Background(), &status.Host,
	)
}
