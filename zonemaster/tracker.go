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

package zonemaster

import (
	"time"

	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/hooto/hlog4g/hlog"

	"code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/status"
)

var (
	zm_leader_refreshed int64 = 0
)

func zone_tracker() {

	var (
		force_refresh = false
	)

	if status.Host.Operate == nil {
		hlog.Printf("info", "status.Host.Operate")
		return
	}

	// is zone-master
	if !status.IsZoneMaster() {
		hlog.Printf("debug", "status.IsZoneMaster SKIP")
		return
	}

	// if leader active
	leader_path := losapi.NsZoneSysMasterLeader(status.Host.Operate.ZoneId)
	if rs := data.ZoneMaster.PvGet(leader_path); rs.NotFound() {

		status.ZoneMasterList.Leader = ""

		if rs2 := data.ZoneMaster.PvNew(
			leader_path,
			status.Host.Meta.Id,
			&skv.PathWriteOptions{
				Ttl: 12000,
			},
		); rs2.OK() {
			status.ZoneMasterList.Leader = rs.Bytex().String()
			force_refresh = true
			hlog.Printf("warn", "new zone-master/leader %s", status.Host.Meta.Id)
		} else {
			hlog.Printf("info", "status.Host.Operate")
			return
		}

	} else if rs.OK() {
		if status.ZoneMasterList.Leader != rs.Bytex().String() {
			status.ZoneMasterList.Leader = rs.Bytex().String()
			force_refresh = true
		}
	} else {
		hlog.Printf("warn", "refresh zone-master leader active failed")
		return
	}

	// is zone-master leader
	if !status.IsZoneMasterLeader() {
		return
	}

	// refresh zone-master leader ttl
	if rs := data.ZoneMaster.PvPut(
		leader_path,
		status.Host.Meta.Id,
		&skv.PathWriteOptions{
			PrevValue: status.Host.Meta.Id,
			Ttl:       12000,
		},
	); !rs.OK() {
		hlog.Printf("warn", "refresh zone-master leader ttl failed")
		return
	}

	if !force_refresh &&
		time.Now().UTC().Unix()-zm_leader_refreshed < 60 {
		hlog.Printf("debug", "zone-master/refresh SKIP")
		return
	}
	zm_leader_refreshed = time.Now().UTC().Unix()

	//
	if status.Zone == nil {

		if rs := data.ZoneMaster.PvGet(losapi.NsZoneSysInfo(status.Host.Operate.ZoneId)); rs.OK() {

			var zone losapi.ResZone
			if err := rs.Decode(&zone); err != nil {
				hlog.Printf("error", "No ZoneInfo Setup")
				return
			}

			if zone.Meta != nil && zone.Meta.Id == status.Host.Operate.ZoneId {
				status.Zone = &zone
			}
		}

		if status.Zone == nil {
			hlog.Printf("error", "No ZoneInfo Setup")
			return
		}
	}

	// TODO
	if rs := data.ZoneMaster.PvScan(losapi.NsZoneSysCell(status.Zone.Meta.Id, ""), "", "", 100); rs.OK() {

		rss := rs.KvList()
		for _, v := range rss {

			var cell losapi.ResCell
			if err := v.Decode(&cell); err == nil {
				status.Zone.SyncCell(cell)
			}
		}
	}

	// refresh zone-master list
	if rs := data.ZoneMaster.PvScan(
		losapi.NsZoneSysMasterNode(status.Host.Operate.ZoneId, ""), "", "", 100); !rs.OK() {
		hlog.Printf("warn", "refresh zone-master list failed")
		return
	} else {

		rss := rs.KvList()
		zms := losapi.ResZoneMasterList{
			Leader: status.Host.Meta.Id,
		}

		for _, v := range rss {

			var o losapi.ResZoneMasterNode
			if err := v.Decode(&o); err == nil {
				zms.Sync(o)
			}
		}

		if len(zms.Items) > 0 {
			status.ZoneMasterList.SyncList(zms)
		}
	}

	// refresh host keys
	if rs := data.ZoneMaster.PvScan(
		losapi.NsZoneSysHostSecretKey(status.Host.Operate.ZoneId, ""), "", "", 1000); rs.OK() {

		rs.KvEach(func(v *skv.ResultEntry) int {
			status.ZoneHostSecretKeys.Set(string(v.Key), v.Bytex().String())
			return 0
		})

	} else {
		hlog.Printf("warn", "refresh host key list failed")
	}

	// refresh host list
	if rs := data.ZoneMaster.PvScan(
		losapi.NsZoneSysHost(status.Host.Operate.ZoneId, ""), "", "", 1000); !rs.OK() {
		hlog.Printf("warn", "refresh host list failed")
		return
	} else {

		rss := rs.KvList()

		for _, v := range rss {

			var o losapi.ResHost
			if err := v.Decode(&o); err == nil {

				if o.Operate == nil {
					o.Operate = &losapi.ResHostOperate{}
				} else {
					// o.Operate.PortUsed.Clean()
				}

				status.ZoneHostList.Sync(o)
			} else {
				// TODO
			}
		}

		if !status.ZoneHostListImported {

			if rs := data.ZoneMaster.PvScan(
				losapi.NsZonePodInstance(status.Host.Operate.ZoneId, ""), "", "", 10000,
			); rs.OK() {

				rss := rs.KvList()

				for _, v := range rss {

					var pod losapi.Pod
					if err := v.Decode(&pod); err != nil {
						continue
					}

					for _, opRep := range pod.Operate.Replicas {

						host := status.ZoneHostList.Item(opRep.Node)
						if host == nil {
							continue
						}

						for _, v := range opRep.Ports {

							if v.HostPort == 0 {
								continue
							}

							if host.OpPortAlloc(v.HostPort) == 0 {
								continue
							}

							hlog.Printf("warn", "refresh host:%s.operate.ports", host.Meta.Id)

							data.ZoneMaster.PvPut(
								losapi.NsZoneSysHost(status.Host.Operate.ZoneId, host.Meta.Id),
								host,
								&skv.PathWriteOptions{
									Force: true,
								},
							)
						}
					}
				}
			}
		}

		if len(status.ZoneHostList.Items) > 0 {
			status.ZoneHostListImported = true
		}

		// hlog.Printf("info", "zone-master/host-list %d refreshed", len(status.ZoneHostList.Items))
	}

	// hlog.Printf("debug", "zone-master/status refreshed")
}
