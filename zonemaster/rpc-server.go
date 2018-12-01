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
		return nil, errors.New("No ZoneMasterLeader Found")
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
		zm_host_addr_change(opts, host.Spec.PeerLanAddr)
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

			var stats_index inapi.PbStatsIndexFeed
			if rs := data.ZoneMaster.KvProgGet(pk); rs.OK() {
				rs.Decode(&stats_index)
				if stats_index.Time < 1 {
					continue
				}
			}

			stats_index.Time = v.Time
			for _, entry := range v.Items {
				for _, sv := range entry.Items {
					stats_index.Sync(entry.Name, sv.Time, sv.Value)
				}
			}

			if len(stats_index.Items) > 0 {
				data.ZoneMaster.KvProgPut(
					pk,
					skv.NewKvEntry(stats_index),
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

	// tn := uint32(time.Now().Unix())

	// PodReplica Status
	for _, repStatus := range opts.Prs {

		if repStatus.Stats != nil {

			arrs := inapi.NewPbStatsIndexList(600, 60)

			for _, entry := range repStatus.Stats.Items {
				for _, v2 := range entry.Items {
					arrs.Sync(entry.Name, v2.Time, v2.Value)
				}
			}

			for _, iv := range arrs.Items {

				repStatsKey := inapi.NsZonePodRepStats(
					status.ZoneId, repStatus.PodId, repStatus.RepId, "sys", iv.Time)

				var stats_index inapi.PbStatsIndexFeed
				if rs := data.ZoneMaster.KvProgGet(repStatsKey); rs.OK() {
					rs.Decode(&stats_index)
					if stats_index.Time < 1 {
						continue
					}
				}

				stats_index.Time = iv.Time
				for _, entry := range iv.Items {
					for _, sv := range entry.Items {
						stats_index.Sync(entry.Name, sv.Time, sv.Value)
					}
				}

				if len(stats_index.Items) > 0 {
					data.ZoneMaster.KvProgPut(
						repStatsKey,
						skv.NewKvEntry(stats_index),
						&skv.KvProgWriteOptions{
							Expired: uint64(time.Now().Add(30 * 24 * time.Hour).UnixNano()),
						},
					)
				}
			}

			repStatus.Stats = nil
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

		if repStatus.OpLog == nil {
			repStatus.OpLog = inapi.NewPbOpLogSets(inapi.NsZonePodOpRepKey(repStatus.PodId, repStatus.RepId), 0)
		}

		if prevRepStatus := podStatus.RepGet(repStatus.RepId); prevRepStatus != nil && prevRepStatus.OpLog != nil {

			if repStatus.OpLog.Version <= prevRepStatus.OpLog.Version {

				for _, vlog := range prevRepStatus.OpLog.Items {
					repStatus.OpLog.LogSetEntry(vlog)
				}
			}
		}

		// inapi.ObjPrint(repStatus.PodId, repStatus)
		// fmt.Println(repStatus.PodId, inapi.OpActionStrings(repStatus.Action))
		podStatus.RepSync(repStatus)

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

	hostBound := &inapi.ResHostBound{
		Masters:              &status.ZoneMasterList,
		ExpPsmaps:            status.ZonePodServiceMaps,
		ZoneInpackServiceUrl: config.Config.InpackServiceUrl,
	}

	// TODO
	bk := inapi.NsZoneHostBoundPodRep(status.ZoneId, opts.Meta.Id, "", 0)
	rss := data.ZoneMaster.PvScan(bk, "", "", 1000).KvList()
	hlog.Printf("debug", "zone-master/rpc-server, host (%s) bound pods %d",
		opts.Meta.Id, len(rss))
	for _, v := range rss {
		var bpod inapi.Pod
		if err := v.Decode(&bpod); err != nil {
			continue
		}

		if bpod.Operate.Replica == nil {
			continue
		}

		if inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			if uint32(time.Now().Unix())-bpod.Operate.Operated > inapi.PodDestroyTTL {
				bk2 := inapi.NsZoneHostBoundPodRep(status.ZoneId, opts.Meta.Id, bpod.Meta.ID, bpod.Operate.Replica.RepId)
				data.ZoneMaster.PvDel(bk2, nil)
				hlog.Printf("warn", "zone-master/pod/bound remove %s", bpod.Meta.ID)
				continue
			}
		}

		// inapi.ObjPrint("rpc/server/"+opts.Meta.Id, v)
		js, _ := json.Encode(bpod, "")
		hostBound.ExpPods = append(hostBound.ExpPods, string(js))
	}

	return hostBound, nil
}

func zm_host_addr_change(host *inapi.ResHost, addr_prev string) {

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

			hlog.Printf("warn", "ZoneMaster status.Zone.LanAddrs %s->%s",
				addr_prev, host.Spec.PeerLanAddr)

			break
		}
	}

	//
	masters := []inapi.HostNodeAddress{}
	for i, v := range status.ZoneMasterList.Items {

		if v.Addr == addr_prev {

			status.ZoneMasterList.Items[i].Addr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "ZoneMaster status.ZoneMasterList.Items %s->%s",
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

			hlog.Printf("warn", "ZoneMaster status.ZoneHostList.Items %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
		}
	}
	for i, v := range status.LocalZoneMasterList.Items {

		if v.Addr == addr_prev {

			status.LocalZoneMasterList.Items[i].Addr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "ZoneMaster status.LocalZoneMasterList.Items %s->%s",
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

					hlog.Printf("warn", "ZoneMaster GlobalSysZone %s->%s",
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

				hlog.Printf("warn", "ZoneMaster NsZoneSysMasterNode %s->%s",
					addr_prev, host.Spec.PeerLanAddr)
			}
		}
	}

	hlog.Printf("warn", "ZoneMaster %s->%s", addr_prev, host.Spec.PeerLanAddr)
}
