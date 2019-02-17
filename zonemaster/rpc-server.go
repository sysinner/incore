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
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lynkdb/iomix/skv"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/auth"
	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	zmMu sync.Mutex
)

type ApiZoneMaster struct{}

func (s *ApiZoneMaster) HostStatusSync(
	ctx context.Context,
	opts *inapi.ResHost,
) (*inapi.ResHostBound, error) {

	// fmt.Println("host status sync", opts.Meta.Id, opts.Status.Uptime)
	if !status.IsZoneMasterLeader() {
		return &inapi.ResHostBound{
			Masters: &status.ZoneMasterList,
		}, nil
	}

	if opts == nil || opts.Meta == nil {
		return nil, errors.New("BadArgs")
	}

	if err := auth.TokenValid(ctx); err != nil {
		return nil, err
	}

	//
	host := status.ZoneHostList.Item(opts.Meta.Id)
	if host == nil || host.Meta == nil {
		return nil, errors.New("BadArgs No Host Found " + opts.Meta.Id)
	}

	//
	if opts.Spec.PeerLanAddr != "" && opts.Spec.PeerLanAddr != host.Spec.PeerLanAddr {
		zmHostAddrChange(opts, host.Spec.PeerLanAddr)
	}

	if opts.Status != nil && opts.Status.Stats != nil {

		arrs := inapi.NewPbStatsIndexList(600, 60)
		for _, v := range opts.Status.Stats.Items {
			for _, v2 := range v.Items {
				arrs.Sync(v.Name, v2.Time, v2.Value)
			}
		}

		for _, v := range arrs.Items {

			pk := inapi.NsZoneSysHostStats(status.ZoneId, opts.Meta.Id, v.Time)

			var statsIndex inapi.PbStatsIndexFeed
			if rs := data.ZoneMaster.KvProgGet(pk); rs.OK() {
				rs.Decode(&statsIndex)
				if statsIndex.Time < 1 {
					continue
				}
			}

			statsIndex.Time = v.Time
			for _, entry := range v.Items {
				for _, sv := range entry.Items {
					statsIndex.Sync(entry.Name, sv.Time, sv.Value)
				}
			}

			if len(statsIndex.Items) > 0 {
				data.ZoneMaster.KvProgPut(
					pk,
					skv.NewKvEntry(statsIndex),
					&skv.KvProgWriteOptions{
						Expired: uint64(time.Now().Add(30 * 24 * time.Hour).UnixNano()),
					},
				)
			}
		}
		opts.Status.Stats = nil
	}

	//
	if host.SyncStatus(*opts) {
		host.Status.Updated = uint32(time.Now().Unix())
		data.ZoneMaster.PvPut(inapi.NsZoneSysHost(status.ZoneId, opts.Meta.Id), host, nil)
		// hlog.Printf("info", "zone-master/host %s updated", opts.Meta.Id)
	}

	tn := uint32(time.Now().Unix())
	/**
	hlog.Printf("debug", "zone-master/host %s, rep status %d updated",
		opts.Meta.Id, len(opts.Prs))
	*/

	// PodReplica Status
	for _, repStatus := range opts.Prs {

		if repStatus.PodId == "" {
			continue
		}

		podActive := status.ZonePodList.Items.Get(repStatus.PodId)
		if podActive == nil {
			continue
		}

		ctrRep := podActive.Operate.Replicas.Get(repStatus.RepId)
		if ctrRep == nil {
			continue
		}

		if ctrRep.Node != opts.Meta.Id &&
			(ctrRep.Next == nil || ctrRep.Next.Node != opts.Meta.Id) {
			continue
		}

		if ctrRep.Node == opts.Meta.Id && repStatus.Stats != nil {

			arrs := inapi.NewPbStatsIndexList(600, 60)

			for _, entry := range repStatus.Stats.Items {
				for _, v2 := range entry.Items {
					arrs.Sync(entry.Name, v2.Time, v2.Value)
				}
			}

			for _, iv := range arrs.Items {

				repStatsKey := inapi.NsZonePodRepStats(
					status.ZoneId, repStatus.PodId, repStatus.RepId, "sys", iv.Time)

				var statsIndex inapi.PbStatsIndexFeed
				if rs := data.ZoneMaster.KvProgGet(repStatsKey); rs.OK() {
					rs.Decode(&statsIndex)
					if statsIndex.Time < 1 {
						continue
					}
				}

				statsIndex.Time = iv.Time
				for _, entry := range iv.Items {
					for _, sv := range entry.Items {
						statsIndex.Sync(entry.Name, sv.Time, sv.Value)
					}
				}

				if len(statsIndex.Items) > 0 {
					data.ZoneMaster.KvProgPut(
						repStatsKey,
						skv.NewKvEntry(statsIndex),
						&skv.KvProgWriteOptions{
							Expired: uint64(time.Now().Add(30 * 24 * time.Hour).UnixNano()),
						},
					)
				}
			}
		}
		repStatus.Stats = nil

		if repStatus.OpLog == nil {
			repStatus.OpLog = inapi.NewPbOpLogSets(
				inapi.NsZonePodOpRepKey(repStatus.PodId, repStatus.RepId), 0)
		}

		podStatus := status.ZonePodStatusList.Get(repStatus.PodId)
		if podStatus == nil {
			podStatusKey := inapi.NsZonePodStatus(status.ZoneId, repStatus.PodId)
			if rs := data.ZoneMaster.PvGet(podStatusKey); rs.OK() {
				var item inapi.PodStatus
				if err := rs.Decode(&item); err == nil {
					podStatus = &item
				}
			} else if rs.NotFound() {
				podStatus = &inapi.PodStatus{
					PodId: repStatus.PodId,
				}
			}
			if podStatus == nil {
				continue
			}
			status.ZonePodStatusList.Set(podStatus)
		}

		if ctrRep.Node == opts.Meta.Id {

			if prevRepStatus := podStatus.RepGet(repStatus.RepId); prevRepStatus != nil {

				if prevRepStatus.OpLog == nil || prevRepStatus.OpLog.Version < podActive.Operate.Version {
					prevRepStatus.OpLog = inapi.NewPbOpLogSets(
						inapi.NsZonePodOpRepKey(repStatus.PodId, repStatus.RepId), podActive.Operate.Version)
				}

				hlog.Printf("debug", "zm/rpc-server host %s, rep %s#%d, prev-oplog v%d n%d, status-oplog v%d n%d",
					opts.Meta.Id, repStatus.PodId, repStatus.RepId,
					prevRepStatus.OpLog.Version, len(prevRepStatus.OpLog.Items),
					repStatus.OpLog.Version, len(repStatus.OpLog.Items),
				)

				if repStatus.OpLog.Version == prevRepStatus.OpLog.Version {
					for _, vlog := range repStatus.OpLog.Items {
						prevRepStatus.OpLog.LogSetEntry(vlog)
					}
					repStatus.OpLog = prevRepStatus.OpLog
				}
			}
			repStatus.Node = opts.Meta.Id

			hlog.Printf("debug", "zm/rpc-server host %s, rep %s#%d, status %s",
				opts.Meta.Id, repStatus.PodId, repStatus.RepId,
				strings.Join(inapi.OpActionStrings(repStatus.Action), "|"),
			)
		}

		if ctrRep.Next != nil && ctrRep.Next.Node == opts.Meta.Id {

			if inapi.OpActionAllow(repStatus.Action, inapi.OpActionMigrated) &&
				!inapi.OpActionAllow(ctrRep.Next.Action, inapi.OpActionMigrated) {
				// NOTICE
				ctrRep.Next.Action = ctrRep.Next.Action | inapi.OpActionMigrated
				hlog.Printf("warn", "zm/rpc-server rep %s#%d, action %s, nextAction %s, Migrate IN",
					repStatus.PodId, repStatus.RepId,
					strings.Join(inapi.OpActionStrings(ctrRep.Action), "|"),
					strings.Join(inapi.OpActionStrings(ctrRep.Next.Action), "|"),
				)

				repStatus.OpLog.LogSet(
					podActive.Operate.Version,
					inapi.NsOpLogZoneRepMigrateDone, inapi.PbOpLogOK,
					fmt.Sprintf("migrate rep %s:%d, data sync done",
						repStatus.PodId, repStatus.RepId),
				)
			}

		} else {

			repStatus.Updated = tn

			// inapi.ObjPrint(repStatus.PodId, repStatus)
			// fmt.Println(repStatus.PodId, inapi.OpActionStrings(repStatus.Action))
			podStatus.RepSync(repStatus)
		}

		/**
		if rs := data.ZoneMaster.PvPut(podStatusKey, podStatus, nil); !rs.OK() {
			hlog.Printf("error", "zone-master/pod StatusSync %s Failed",
				podStatus.Id)
			return nil, errors.New("Server Error")
		}
		*/

		// hlog.Printf("info", "zone-master/pod StatusSync %s/%d phase:%s updated", v.Id, v.Rep, v.Phase)
	}

	// hlog.Printf("info", "zone-master/rpc-server hostlet synced pods:%d", len(opts.Prs))

	var (
		hostBound = &inapi.ResHostBound{
			Masters:              &status.ZoneMasterList,
			ZoneInpackServiceUrl: config.Config.InpackServiceUrl,
		}
	)

	// Control Replica
	for _, bpod := range status.ZonePodList.Items {

		for _, ctrRep := range bpod.Operate.Replicas {

			if ctrRep.PrevNode == opts.Meta.Id && ctrRep.Next == nil {

				hostBound.ExpBoxRemoves = append(hostBound.ExpBoxRemoves,
					inapi.PodRepInstanceName(bpod.Meta.ID, ctrRep.RepId))
				continue
			}

			if ctrRep.Node != opts.Meta.Id &&
				(ctrRep.Next == nil || ctrRep.Next.Node != opts.Meta.Id) {
				continue
			}

			if ctrRep.Node == opts.Meta.Id {

				if inapi.OpActionAllow(ctrRep.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
					hostBound.ExpBoxRemoves = append(hostBound.ExpBoxRemoves,
						inapi.PodRepInstanceName(bpod.Meta.ID, ctrRep.RepId))
					continue
				}

				if inapi.OpActionAllow(ctrRep.Action, inapi.OpActionStop|inapi.OpActionStopped) &&
					!inapi.OpActionAllow(ctrRep.Action, inapi.OpActionMigrate) {
					hostBound.ExpBoxStops = append(hostBound.ExpBoxStops,
						inapi.PodRepInstanceName(bpod.Meta.ID, ctrRep.RepId))
					continue
				}
			}

			podRep := inapi.PodRep{
				Meta:    bpod.Meta,
				Spec:    bpod.Spec,
				Apps:    bpod.Apps,
				Operate: bpod.Operate,
			}

			if ctrRep.Next != nil && ctrRep.Next.Node == opts.Meta.Id {

				if ctrRep.Action == (inapi.OpActionMigrate | inapi.OpActionStop) {
					continue
				}

				podRep.Replica = inapi.PodOperateReplica{
					RepId:   ctrRep.RepId,
					Node:    ctrRep.Next.Node,
					Action:  ctrRep.Next.Action,
					ResCpu:  ctrRep.Next.ResCpu,
					ResMem:  ctrRep.Next.ResMem,
					VolSys:  ctrRep.Next.VolSys,
					Ports:   ctrRep.Next.Ports,
					Options: ctrRep.Options,
				}
			} else {
				podRep.Replica = inapi.PodOperateReplica{
					RepId:   ctrRep.RepId,
					Node:    ctrRep.Node,
					Action:  ctrRep.Action,
					ResCpu:  ctrRep.ResCpu,
					ResMem:  ctrRep.ResMem,
					VolSys:  ctrRep.VolSys,
					Ports:   ctrRep.Ports,
					Options: ctrRep.Options,
					Next:    ctrRep.Next,
				}

				/**
				// bugfix
				if inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionMigrate) &&
					!inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionStop) &&
					!inapi.OpActionAllow(podRep.Replica.Action, inapi.OpActionDestroy) {
					podRep.Replica.Action = podRep.Replica.Action | inapi.OpActionStop
					ctrRep.Action = ctrRep.Action | inapi.OpActionStop
				}
				*/
			}

			podRep.Replica.Updated = tn

			js, _ := json.Encode(podRep, "")
			hostBound.ExpPods = append(hostBound.ExpPods, string(js))

			hlog.Printf("debug", "zm/rpc-server ctrl host %s, rep %s#%d, podAction %s, repAction %s, removes %s",
				podRep.Replica.Node,
				bpod.Meta.ID, podRep.Replica.RepId,
				strings.Join(inapi.OpActionStrings(bpod.Operate.Action), ","),
				strings.Join(inapi.OpActionStrings(podRep.Replica.Action), ","),
				strings.Join(hostBound.ExpBoxRemoves, ","))
		}
	}

	hlog.Printf("debug", "zm/rpc-server Ctr host %s, removes %d",
		opts.Meta.Id,
		len(hostBound.ExpBoxRemoves))

	return hostBound, nil
}

func zmHostAddrChange(host *inapi.ResHost, addr_prev string) {

	zmMu.Lock()
	defer zmMu.Unlock()

	if status.ZoneId == "" {
		return
	}

	for _, v := range status.ZoneHostList.Items {

		if host.Spec.PeerLanAddr == v.Spec.PeerLanAddr &&
			host.Meta.Id != v.Meta.Id {
			return
		}
	}

	if status.Host.Meta.Id == host.Spec.PeerLanAddr {
		status.Host.Spec.PeerLanAddr = host.Spec.PeerLanAddr
	}

	for i, p := range status.Zone.LanAddrs {

		if addr_prev == p {

			status.Zone.LanAddrs[i] = host.Spec.PeerLanAddr

			hlog.Printf("warn", "zm status.Zone.LanAddrs %s->%s",
				addr_prev, host.Spec.PeerLanAddr)

			break
		}
	}

	//
	masters := []inapi.HostNodeAddress{}
	for i, v := range status.ZoneMasterList.Items {

		if v.Addr == addr_prev {

			status.ZoneMasterList.Items[i].Addr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "zm status.ZoneMasterList.Items %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
		}

		masters = append(masters, inapi.HostNodeAddress(status.ZoneMasterList.Items[i].Addr))
	}
	if len(masters) > 0 {
		config.Config.Masters = masters
		config.Config.Sync()
	}

	//
	for i, v := range status.ZoneHostList.Items {

		if v.Spec.PeerLanAddr == addr_prev {

			status.ZoneHostList.Items[i].Spec.PeerLanAddr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "zm status.ZoneHostList.Items %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
		}
	}
	for i, v := range status.LocalZoneMasterList.Items {

		if v.Addr == addr_prev {

			status.LocalZoneMasterList.Items[i].Addr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "zm status.LocalZoneMasterList.Items %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
			break
		}
	}

	//
	/*
		if host.Spec.PeerLanAddr != addr_prev {

			data.ZoneMaster.PvPut(inapi.NsZoneSysHost(status.ZoneId, host.Meta.Id), host, nil)

			hlog.Printf("warn", "ZoneMaster NsZoneSysHost %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
		}
	*/

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalSysZone(status.ZoneId)); rs.OK() {

		var zone inapi.ResZone
		if err := rs.Decode(&zone); err == nil {

			for i, p := range zone.LanAddrs {

				if addr_prev == p {

					zone.LanAddrs[i] = host.Spec.PeerLanAddr

					hlog.Printf("warn", "zm GlobalSysZone %s->%s",
						addr_prev, host.Spec.PeerLanAddr)

					// TOPO
					if rs := data.GlobalMaster.PvPut(inapi.NsGlobalSysZone(status.ZoneId), zone, nil); rs.OK() {
						data.ZoneMaster.PvPut(inapi.NsZoneSysInfo(status.ZoneId), zone, nil)
					}

					break
				}
			}
		}
	}

	if rs := data.ZoneMaster.PvGet(inapi.NsZoneSysMasterNode(status.ZoneId, host.Meta.Id)); rs.OK() {

		var obj inapi.ResZoneMasterNode
		if err := rs.Decode(&obj); err == nil {

			if obj.Addr == addr_prev {

				data.ZoneMaster.PvPut(inapi.NsZoneSysMasterNode(status.ZoneId, host.Meta.Id), inapi.ResZoneMasterNode{
					Id:     host.Meta.Id,
					Addr:   host.Spec.PeerLanAddr,
					Action: 1,
				}, nil)

				hlog.Printf("warn", "zm NsZoneSysMasterNode %s->%s",
					addr_prev, host.Spec.PeerLanAddr)
			}
		}
	}

	hlog.Printf("info", "zm/host/addr %s->%s", addr_prev, host.Spec.PeerLanAddr)
}
