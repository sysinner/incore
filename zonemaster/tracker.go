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

package zonemaster

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"

	iam_api "github.com/hooto/iam/iamapi"
	iam_db "github.com/hooto/iam/store"
)

var (
	zmLeaderLastRefreshed   int64  = 0
	zmPodOperateHangTimeout uint32 = 86400 * 10
)

func zoneTracker() {

	if status.Host.Operate == nil {
		hlog.Printf("info", "status.Host.Operate")
		return
	}

	// is zone-master
	if !status.IsZoneMaster() {
		hlog.Printf("debug", "status.IsZoneMaster SKIP")
		return
	}

	if status.ZoneId == "" {
		hlog.Printf("error", "config.json host/zone_id Not Found")
		return
	}

	// if leader active
	active, forceRefresh := zmWorkerMasterLeaderActive()
	if !active {
		return
	}

	// refresh host keys
	if len(status.ZoneHostSecretKeys) == 0 {
		if rs := data.ZoneMaster.PvScan(
			inapi.NsZoneSysHostSecretKey(status.Host.Operate.ZoneId, ""), "", "", 1000); rs.OK() {

			rs.KvEach(func(v *skv.ResultEntry) int {
				status.ZoneHostSecretKeys.Set(string(v.Key), v.Bytex().String())
				return 0
			})

		} else {
			hlog.Printf("warn", "refresh host key list failed")
		}
	}

	// is zone-master leader
	if !status.IsZoneMasterLeader() {
		status.ZoneLeaded = 0
		return
	}

	// refresh zone-master leader ttl
	if rs := data.ZoneMaster.KvPut(
		inapi.NsKvZoneSysMasterLeader(status.Host.Operate.ZoneId),
		status.Host.Meta.Id,
		&skv.KvWriteOptions{
			// PrevSum: pv.Crc32(), // TODO BUG
			Ttl: 12000,
		},
	); !rs.OK() {
		hlog.Printf("warn", "zm/zone-master/leader ttl refresh failed "+rs.String())
		return
	}

	zmWorkerSysConfigRefresh()

	//
	zmWorkerPodListStatusRefresh()

	//
	if !forceRefresh &&
		time.Now().Unix()-zmLeaderLastRefreshed < 60 {
		hlog.Printf("debug", "zm/refresh SKIP")
		return
	}
	zmLeaderLastRefreshed = time.Now().Unix()

	//
	if err := zmWorkerZoneAccessKeySetup(); err != nil {
		hlog.Printf("warn", "zm/zone-access-key/setup error %s", err.Error())
		return
	}

	zmWorkerZoneCellRefresh()

	if err := zmWorkerGlobalZoneListRefresh(); err != nil {
		hlog.Printf("warn", "zm/global-zone-list/refresh error %s", err.Error())
		return
	}

	// refresh zone-master list
	if err := zmWorkerZoneMasterListRefresh(); err != nil {
		hlog.Printf("warn", "zm/master-list/refresh error %s", err.Error())
		return
	}

	// refresh host keys
	if err := zmWorkerZoneHostKeyListRefresh(); err != nil {
		hlog.Printf("warn", "zm/host-key-list/refresh error %s", err.Error())
		return
	}

	// refresh host list
	if err := zmWorkerZoneHostListRefresh(); err != nil {
		hlog.Printf("warn", "refresh host list err %s", err.Error())
		return
	}

	// hlog.Printf("debug", "zm/status refreshed")
}

func zmWorkerMasterLeaderActive() (bool, bool) {
	// if leader active
	var (
		forceRefresh = false
		zmLeaderKey  = inapi.NsKvZoneSysMasterLeader(status.Host.Operate.ZoneId)
	)
	if rs := data.ZoneMaster.KvGet(zmLeaderKey); rs.NotFound() {

		if !inapi.ResSysHostIdReg.MatchString(status.Host.Meta.Id) {
			return false, forceRefresh
		}

		if rs2 := data.ZoneMaster.KvNew(
			zmLeaderKey,
			status.Host.Meta.Id,
			&skv.KvWriteOptions{
				Ttl: 12000,
			},
		); rs2.OK() {
			status.ZoneMasterList.Leader = status.Host.Meta.Id
			forceRefresh = true
			hlog.Printf("warn", "zm/zone-master/leader new %s", status.Host.Meta.Id)
			status.ZoneLeaded = time.Now().Unix()
		} else {
			hlog.Printf("info", "status.Host.Operate")
			return false, forceRefresh
		}

	} else if rs.OK() {
		hostId := rs.String()
		if inapi.ResSysHostIdReg.MatchString(hostId) &&
			status.ZoneMasterList.Leader != hostId {
			status.ZoneMasterList.Leader = hostId
			forceRefresh = true
		}
	} else {
		hlog.Printf("warn", "zm/zone-master/leader active refresh failed")
		return false, forceRefresh
	}

	return true, forceRefresh
}

func zmWorkerZoneAccessKeySetup() error {
	//
	if status.Zone == nil {

		if rs := data.ZoneMaster.PvGet(inapi.NsZoneSysInfo(status.Host.Operate.ZoneId)); rs.OK() {

			var zone inapi.ResZone
			if err := rs.Decode(&zone); err != nil {
				return errors.New("ZoneAccessKey " + err.Error())
			}

			if zone.Meta != nil && zone.Meta.Id == status.Host.Operate.ZoneId {
				status.Zone = &zone
			}
		}

		if status.Zone == nil {
			return fmt.Errorf("Zone (%s) Not Found", status.Host.Operate.ZoneId)
		}

		init_if := iam_api.AccessKey{
			User: "sysadmin",
			Bounds: []iam_api.AccessKeyBound{{
				Name: "sys/zm/" + status.Host.Operate.ZoneId,
			}},
			Description: "ZoneMaster AccCharge",
		}
		if v, ok := status.Zone.OptionGet("iam/acc_charge/access_key"); ok {
			init_if.AccessKey = v
		}
		if v, ok := status.Zone.OptionGet("iam/acc_charge/secret_key"); ok {
			init_if.SecretKey = v
		}

		if init_if.AccessKey == "" || init_if.SecretKey == "" {
			//
			init_if.AccessKey = "00" + idhash.HashToHexString(
				[]byte(fmt.Sprintf("sys/zone/iam_acc_charge/ak/%s", status.Host.Operate.ZoneId)), 14)
			init_if.SecretKey = idhash.HashToBase64String(
				idhash.AlgSha256, []byte(config.Config.Host.SecretKey), 40)
			//
			status.Zone.OptionSet("iam/acc_charge/access_key", init_if.AccessKey)
			status.Zone.OptionSet("iam/acc_charge/secret_key", init_if.SecretKey)
			//
			if rs := data.ZoneMaster.PvPut(inapi.NsGlobalSysZone(status.Host.Operate.ZoneId), status.Zone, nil); !rs.OK() {
				return fmt.Errorf("Zone #%s AccessKey Reset Error",
					status.Host.Operate.ZoneId)
			}
			if rs := data.ZoneMaster.PvPut(inapi.NsZoneSysInfo(status.Host.Operate.ZoneId), status.Zone, nil); !rs.OK() {
				return fmt.Errorf("Zone #%s AccessKey Reset Error",
					status.Host.Operate.ZoneId)
			}
			hlog.Printf("warn", "zone #%s, reset iam/acc_charge/key, access_key %s, secret_key %s...",
				status.Host.Operate.ZoneId, init_if.AccessKey, init_if.SecretKey[:8])
		}

		iam_db.AccessKeyInitData(init_if)
	}

	return nil
}

func zmWorkerZoneCellRefresh() {
	// TODO
	if rs := data.ZoneMaster.PvScan(inapi.NsZoneSysCell(status.Zone.Meta.Id, ""), "", "", 100); rs.OK() {

		rss := rs.KvList()
		for _, v := range rss {

			var cell inapi.ResCell
			if err := v.Decode(&cell); err == nil {
				status.Zone.SyncCell(cell)
			}
		}
	}
}

func zmWorkerGlobalZoneListRefresh() error {
	// refresh global zones
	rs := data.GlobalMaster.PvScan(
		inapi.NsGlobalSysZone(""), "", "", 50)
	if !rs.OK() {
		return errors.New("db/scan error")
	}

	rss := rs.KvList()

	for _, v := range rss {

		var o inapi.ResZone
		if err := v.Decode(&o); err == nil {
			found := false
			for i, pv := range status.GlobalZones {
				if pv.Meta.Id != o.Meta.Id {
					continue
				}
				found = true

				if pv.Meta.Updated < o.Meta.Updated {
					status.GlobalZones[i] = &o
				}
			}

			//
			if rs := data.GlobalMaster.PvScan(inapi.NsGlobalSysCell(o.Meta.Id, ""), "", "", 100); rs.OK() {

				rss2 := rs.KvList()
				for _, v2 := range rss2 {

					var cell inapi.ResCell
					if err := v2.Decode(&cell); err == nil {
						o.SyncCell(cell)
					}
				}
			}

			if !found {
				status.GlobalZones = append(status.GlobalZones, &o)
			}

			if status.Zone != nil && o.Meta.Id == status.Zone.Meta.Id {
				if o.Meta.Updated > status.Zone.Meta.Updated {
					status.Zone = &o
					data.ZoneMaster.PvPut(inapi.NsZoneSysInfo(status.Host.Operate.ZoneId), status.Zone, nil)
				}
			}
		}
	}

	return nil
}

func zmWorkerZoneHostListRefresh() error {
	rs := data.ZoneMaster.PvScan(
		inapi.NsZoneSysHost(status.Host.Operate.ZoneId, ""), "", "", 1000)
	if !rs.OK() {
		hlog.Printf("warn", "refresh host list failed")
		return errors.New("db/scan error")
	}

	rss := rs.KvList()
	cell_counter := map[string]int32{}

	for _, v := range rss {

		var o inapi.ResHost
		if err := v.Decode(&o); err == nil {

			if o.Operate == nil {
				o.Operate = &inapi.ResHostOperate{}
			} else {
				// o.Operate.PortUsed.Clean()
			}
			cell_counter[o.Operate.CellId]++

			status.ZoneHostList.Sync(o)
			if gn := status.GlobalHostList.Item(o.Meta.Id); gn == nil {
				if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysHost(o.Operate.ZoneId, o.Meta.Id)); rs.NotFound() {
					data.GlobalMaster.PvPut(inapi.NsGlobalSysHost(o.Operate.ZoneId, o.Meta.Id), o, nil)
				}
			}
			status.GlobalHostList.Sync(o)

			// hlog.Printf("info", "refresh host refresh %s", o.Meta.Id)

		} else {
			// TODO
			hlog.Printf("error", "refresh host list %s", err.Error())
		}

		// hlog.Printf("info", "refresh host refresh %d", len(rss))
	}

	if !status.ZoneHostListImported {

		if len(cell_counter) > 0 {
			if rs := data.GlobalMaster.PvScan(inapi.NsGlobalSysCell(status.Host.Operate.ZoneId, ""), "", "", 1000); rs.OK() {
				rss := rs.KvList()
				for _, v := range rss {
					var cell inapi.ResCell
					if err := v.Decode(&cell); err == nil {
						if n, ok := cell_counter[cell.Meta.Id]; ok && n != cell.NodeNum {
							cell.NodeNum = n

							if rs := data.GlobalMaster.PvPut(inapi.NsGlobalSysCell(status.Host.Operate.ZoneId, cell.Meta.Id), cell, nil); rs.OK() {
								data.ZoneMaster.PvPut(inapi.NsZoneSysCell(status.Host.Operate.ZoneId, cell.Meta.Id), cell, nil)
							}
						}
					}
				}
			}
		}

		if rs := data.ZoneMaster.PvScan(
			inapi.NsZonePodInstance(status.Host.Operate.ZoneId, ""), "", "", 10000,
		); rs.OK() {

			rss := rs.KvList()

			for _, v := range rss {

				var pod inapi.Pod
				if err := v.Decode(&pod); err != nil {
					continue
				}

				// hlog.Printf("info", "pod set %s", pod.Meta.ID)
				status.ZonePodList.Items.Set(&pod)

				if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
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

						hlog.Printf("info", "zm/host:%s.operate.ports refreshed", host.Meta.Id)

						data.ZoneMaster.PvPut(
							inapi.NsZoneSysHost(status.Host.Operate.ZoneId, host.Meta.Id),
							host,
							nil,
						)
					}
				}
			}
		}
	}

	if len(status.ZoneHostList.Items) > 0 {
		status.ZoneHostListImported = true
	}

	// hlog.Printf("info", "zm/host-list %d refreshed", len(status.ZoneHostList.Items))
	return nil
}

func zmWorkerZoneHostKeyListRefresh() error {

	rs := data.ZoneMaster.PvScan(
		inapi.NsZoneSysHostSecretKey(status.Host.Operate.ZoneId, ""), "", "", 1000)
	if !rs.OK() {
		return errors.New("db/scan error")
	}

	rs.KvEach(func(v *skv.ResultEntry) int {
		status.ZoneHostSecretKeys.Set(string(v.Key), v.Bytex().String())
		return 0
	})

	return nil
}

func zmWorkerZoneMasterListRefresh() error {

	rs := data.ZoneMaster.PvScan(
		inapi.NsZoneSysMasterNode(status.Host.Operate.ZoneId, ""), "", "", 100)
	if !rs.OK() {
		return errors.New("db/scan error")
	}

	rss := rs.KvList()
	zms := inapi.ResZoneMasterList{
		Leader: status.Host.Meta.Id,
	}

	for _, v := range rss {

		var o inapi.ResZoneMasterNode
		if err := v.Decode(&o); err == nil {
			zms.Sync(o)
		}
	}

	if len(zms.Items) > 0 {
		status.ZoneMasterList.SyncList(&zms)
	}

	return nil
}

var zmWorkerSysConfigRefreshed = uint32(0)

func zmWorkerSysConfigRefresh() {

	tn := uint32(time.Now().Unix())

	if (zmWorkerSysConfigRefreshed + 60) < tn {

		for _, v := range config.SysConfigurators {

			//
			if rs := data.GlobalMaster.KvGet(inapi.NsGlobalSysConfig(v.Name)); rs.OK() {
				var item inapi.SysConfigGroup
				if err := rs.Decode(&item); err == nil {
					status.ZoneSysConfigGroupList.Sync(&item)
				}
			}
		}

		zmWorkerSysConfigRefreshed = tn

		// hlog.Printf("info", "zm/sys-config/refresh %d", len(config.SysConfigurators))
	}
}

// refresh pod's status
func zmWorkerPodListStatusRefresh() {

	tn := uint32(time.Now().Unix())

	for _, pod := range status.ZonePodList.Items {

		if pod.Spec == nil || pod.Spec.Zone != status.Host.Operate.ZoneId {
			continue
		}

		if pod.Operate.ReplicaCap < 1 {
			continue
		}

		var (
			podSync       = false
			podStatusKey  = inapi.NsKvZonePodStatus(status.Host.Operate.ZoneId, pod.Meta.ID)
			podStatusKeyG = inapi.NsKvGlobalPodStatus(status.Host.Operate.ZoneId, pod.Meta.ID)
			podStatus     = status.ZonePodStatusList.Get(pod.Meta.ID)
		)

		if podStatus == nil {
			if rs := data.ZoneMaster.KvGet(podStatusKey); rs.OK() {
				var item inapi.PodStatus
				if err := rs.Decode(&item); err == nil {

					podStatus = &item
				}
			} else if rs.NotFound() {
				podStatus = &inapi.PodStatus{
					PodId: pod.Meta.ID,
				}
			}
			if podStatus == nil {
				continue
			}
			status.ZonePodStatusList.Set(podStatus)
		}

		if podStatus.PodId == "" {
			podStatus.PodId = pod.Meta.ID
		}

		for _, repId := range pod.Operate.ExpMigrates {

			if repId >= uint32(pod.Operate.ReplicaCap) {
				continue
			}

			ctrRep := pod.Operate.Replicas.Get(repId)
			if ctrRep == nil {
				continue
			}

			if ctrRep.Next == nil {
				continue
			}

			repStatus := podStatus.RepGet(repId)
			if repStatus == nil {
				continue
			}

			// logicfix
			if inapi.OpActionAllow(ctrRep.Action, inapi.OpActionMigrate) {

				host := status.ZoneHostList.Item(ctrRep.Node)
				if host != nil {

					var (
						hostPeer = inapi.HostNodeAddress(host.Spec.PeerLanAddr)
						addr     = fmt.Sprintf("%s:%d", hostPeer.IP(), hostPeer.Port()+5)
					)

					if opt, ok := ctrRep.Options.Get("rsync/host"); ok && addr != opt.String() {

						hlog.Printf("warn", "zm/tracker rep %s:%d, set addr from %s to %s",
							pod.Meta.ID, repId,
							opt.String(), addr,
						)

						ctrRep.Options.Set("rsync/host", addr)
						if ctrRep.Next != nil {
							ctrRep.Next.Options.Set("rsync/host", addr)
						}
					}
				}
			}
		}

		// inapi.ObjPrint(pod.Meta.ID, v)

		if len(pod.Operate.OpLog) > 0 {
			podStatus.OpLog = pod.Operate.OpLog
		}

		podStatus.Updated = uint32(time.Now().Unix())
		podStatus.ActionRunning = 0

		repStatusOuts := []uint32{}

		for _, repStatus := range podStatus.Replicas {

			ctrlRep := pod.Operate.Replicas.Get(repStatus.RepId)

			if repStatus.RepId >= uint32(pod.Operate.ReplicaCap) {
				if ctrlRep == nil {
					repStatusOuts = append(repStatusOuts, repStatus.RepId)
				}
				continue
			}

			if inapi.OpActionAllow(repStatus.Action, inapi.OpActionRunning) {
				podStatus.ActionRunning += 1
			}

			if ctrlRep == nil {
				continue
			}

			if opv := inapi.OpActionDesire(ctrlRep.Action, repStatus.Action); opv > 0 {

				if !inapi.OpActionAllow(ctrlRep.Action, opv) {

					hlog.Printf("info", "zm/tracker rep %s:%d, action %s, status %s",
						pod.Meta.ID, repStatus.RepId,
						strings.Join(inapi.OpActionStrings(ctrlRep.Action), ","),
						strings.Join(inapi.OpActionStrings(repStatus.Action), ","),
					)

					// merge rep status's action to control's action
					ctrlRep.Action = ctrlRep.Action | opv

					if inapi.OpActionAllow(ctrlRep.Action, inapi.OpActionDestroy) {
						//
					} else if inapi.OpActionAllow(ctrlRep.Action, inapi.OpActionStart) {
						ctrlRep.Action = inapi.OpActionRemove(ctrlRep.Action, inapi.OpActionStop)
						ctrlRep.Action = inapi.OpActionRemove(ctrlRep.Action, inapi.OpActionStopped)
					} else if inapi.OpActionAllow(ctrlRep.Action, inapi.OpActionStop) {
						ctrlRep.Action = inapi.OpActionRemove(ctrlRep.Action, inapi.OpActionStart)
						ctrlRep.Action = inapi.OpActionRemove(ctrlRep.Action, inapi.OpActionRunning)
					}

					ctrlRep.Updated = tn
					podSync = true
				}
			}
		}

		for _, repId := range repStatusOuts {
			podStatus.RepDel(repId)
			hlog.Printf("info", "zm/rep %s:%d, status out", pod.Meta.ID, repId)
		}

		if rs := data.ZoneMaster.KvPut(podStatusKey, podStatus, nil); !rs.OK() {
			continue
		}

		if rs := data.GlobalMaster.KvPut(podStatusKeyG, podStatus, nil); !rs.OK() {
			continue
		}

		if podSync {
			data.ZoneMaster.PvPut(inapi.NsZonePodInstance(status.ZoneId, pod.Meta.ID), pod, nil)
			// hlog.Printf("info", "pod %s operate db-sync", pod.Meta.ID)
		}

		// inapi.ObjPrint(pod.Meta.ID, podStatus)
		// inapi.ObjPrint(pod.Meta.ID, v)
	}

}
