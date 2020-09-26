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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/auth"
	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	zmMu sync.Mutex
)

type ApiZoneMaster struct {
	inapi.UnimplementedApiZoneMasterServer
}

func (s *ApiZoneMaster) HostConfig(
	ctx context.Context,
	req *inapi.ZoneHostConfigRequest,
) (*inapi.ZoneHostConfigReply, error) {

	if !status.IsZoneMaster() {
		return nil, errors.New("Invalid Zone MainNode Address")
	}

	if !inapi.ResSysHostIdReg.MatchString(req.Id) {
		return nil, errors.New("Invalid Host ID")
	}

	if !inapi.HostNodeAddress(req.LanAddr).Valid() {
		return nil, errors.New("Invalid Host Address")
	}

	if !inapi.ResSysHostSecretKeyReg.MatchString(req.SecretKey) {
		return nil, errors.New("Invalid Host Secret Key")
	}

	if !inapi.ResSysCellIdReg.MatchString(req.CellId) {
		return nil, errors.New("Invalid Cell ID")
	}

	if pc := status.GlobalZoneCell(status.ZoneId, req.CellId); pc == nil {
		return nil, errors.New("cell-id not found")
	}

	dbkey := inapi.NsZoneSysHost(status.ZoneId, req.Id)
	rs := data.DataZone.NewReader(dbkey).Query()
	if !rs.OK() {
		if !rs.NotFound() {
			return nil, errors.New("Server Error, Try again later")
		}

		node := inapi.ResHost{
			Meta: &inapi.ObjectMeta{
				Id:      req.Id,
				Created: uint64(types.MetaTimeNow()),
				Updated: uint64(types.MetaTimeNow()),
			},
			Operate: &inapi.ResHostOperate{
				Action: 1,
				ZoneId: status.ZoneId,
				CellId: req.CellId,
				Pr:     inapi.ResSysHostPriorityDefault,
			},
			Spec: &inapi.ResHostSpec{
				PeerLanAddr: req.LanAddr,
			},
		}

		if rs := data.DataGlobal.NewWriter(
			inapi.NsGlobalSysHost(node.Operate.ZoneId, node.Meta.Id), node).Commit(); !rs.OK() {
			return nil, errors.New("Server Error")
		}

		if rs := data.DataZone.NewWriter(
			inapi.NsZoneSysHost(node.Operate.ZoneId, node.Meta.Id), node).Commit(); !rs.OK() {
			return nil, errors.New("Server Error")
		}

		if rs := data.DataZone.NewWriter(
			inapi.NsZoneSysHostSecretKey(node.Operate.ZoneId, node.Meta.Id), req.SecretKey).Commit(); !rs.OK() {
			return nil, errors.New("Server Error")
		}
	}

	return &inapi.ZoneHostConfigReply{
		ZoneMainNodes: config.Config.Zone.MainNodes,
		ZoneId:        status.ZoneId,
		CellId:        req.CellId,
	}, nil
}

func (s *ApiZoneMaster) HostStatusSync(
	ctx context.Context,
	req *inapi.ResHost,
) (*inapi.ResHostBound, error) {

	// fmt.Println("host status sync", req.Meta.Id, req.Status.Uptime)
	if !status.IsZoneMasterLeader() {
		return &inapi.ResHostBound{
			Masters: &status.ZoneMasterList,
		}, nil
	}

	if req == nil || req.Meta == nil {
		return nil, errors.New("BadArgs")
	}

	if err := auth.TokenValid(ctx); err != nil {
		return nil, err
	}

	//
	host := status.ZoneHostList.Item(req.Meta.Id)
	if host == nil || host.Meta == nil {
		return nil, errors.New("BadArgs No Host Found " + req.Meta.Id)
	}

	//
	if req.Spec.PeerLanAddr != "" && req.Spec.PeerLanAddr != host.Spec.PeerLanAddr {
		zmHostAddrChange(req, host.Spec.PeerLanAddr)
	}

	if req.Status != nil && req.Status.Stats != nil {

		arrs := inapi.NewPbStatsIndexList(600, 60)
		for _, v := range req.Status.Stats.Items {
			for _, v2 := range v.Items {
				arrs.Sync(v.Name, v2.Time, v2.Value)
			}
		}

		for _, v := range arrs.Items {

			pk := inapi.NsKvZoneSysHostStats(status.ZoneId, req.Meta.Id, v.Time)

			var statsIndex inapi.PbStatsIndexFeed
			if rs := data.DataZone.NewReader(pk).Query(); rs.OK() {
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
				data.DataZone.NewWriter(pk, statsIndex).ExpireSet(30 * 86400 * 1000).Commit()
			}
		}
		req.Status.Stats = nil
	}

	//
	if host.SyncStatus(*req) {
		host.Status.Updated = uint32(time.Now().Unix())
		data.DataZone.NewWriter(inapi.NsZoneSysHost(status.ZoneId, req.Meta.Id), host).Commit()
		// hlog.Printf("info", "zone-master/host %s updated", req.Meta.Id)
	}

	tn := uint32(time.Now().Unix())

	// PodReplica Status
	for _, repStatus := range req.Prs {

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

		if ctrRep.Node != req.Meta.Id &&
			(ctrRep.Next == nil || ctrRep.Next.Node != req.Meta.Id) {
			continue
		}

		if ctrRep.Node == req.Meta.Id && repStatus.Stats != nil {

			arrs := inapi.NewPbStatsIndexList(600, 60)

			for _, entry := range repStatus.Stats.Items {
				for _, v2 := range entry.Items {
					arrs.Sync(entry.Name, v2.Time, v2.Value)
				}
			}

			for _, iv := range arrs.Items {

				repStatsKey := inapi.NsKvZonePodRepStats(
					status.ZoneId, repStatus.PodId, repStatus.RepId, "sys", iv.Time)

				var statsIndex inapi.PbStatsIndexFeed
				if rs := data.DataZone.NewReader(repStatsKey).Query(); rs.OK() {
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
					data.DataZone.NewWriter(repStatsKey, statsIndex).ExpireSet(30 * 86400 * 1000).Commit()
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
			continue
		}

		if ctrRep.Node == req.Meta.Id {

			if prevRepStatus := podStatus.RepGet(repStatus.RepId); prevRepStatus != nil {

				if prevRepStatus.OpLog == nil || prevRepStatus.OpLog.Version < podActive.Operate.Version {
					prevRepStatus.OpLog = inapi.NewPbOpLogSets(
						inapi.NsZonePodOpRepKey(repStatus.PodId, repStatus.RepId), podActive.Operate.Version)
				}

				hlog.Printf("debug", "zm/rpc-server host %s, rep %s#%d, prev-oplog v%d n%d, status-oplog v%d n%d",
					req.Meta.Id, repStatus.PodId, repStatus.RepId,
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
			repStatus.Node = req.Meta.Id

			hlog.Printf("debug", "zm/rpc-server host %s, rep %s#%d, status %s",
				req.Meta.Id, repStatus.PodId, repStatus.RepId,
				strings.Join(inapi.OpActionStrings(repStatus.Action), "|"),
			)
		}

		if ctrRep.Next != nil && ctrRep.Next.Node == req.Meta.Id {

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

		// hlog.Printf("info", "zone-master/pod StatusSync %s/%d phase:%s updated", v.Id, v.Rep, v.Phase)
	}

	// hlog.Printf("info", "zone-master/rpc-server hostlet synced pods:%d", len(req.Prs))

	var (
		hostBound = &inapi.ResHostBound{
			Masters:              &status.ZoneMasterList,
			ZoneInpackServiceUrl: config.Config.Zone.InpackServiceUrl,
			ImageServices:        status.Zone.ImageServices,
		}
	)

	// Control Replica
	for _, bpod := range status.ZonePodList.Items {

		for _, ctrRep := range bpod.Operate.Replicas {

			if ctrRep.PrevNode == req.Meta.Id && ctrRep.Next == nil {

				hostBound.ExpBoxRemoves = append(hostBound.ExpBoxRemoves,
					inapi.PodRepInstanceName(bpod.Meta.ID, ctrRep.RepId))
				continue
			}

			if ctrRep.Node != req.Meta.Id &&
				(ctrRep.Next == nil || ctrRep.Next.Node != req.Meta.Id) {
				continue
			}

			if ctrRep.Node == req.Meta.Id {

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

			if ctrRep.Next != nil && ctrRep.Next.Node == req.Meta.Id {

				if ctrRep.Action == (inapi.OpActionMigrate | inapi.OpActionStop) {
					continue
				}

				podRep.Replica = inapi.PodOperateReplica{
					RepId:     ctrRep.RepId,
					Node:      ctrRep.Next.Node,
					Action:    ctrRep.Next.Action,
					ResCpu:    ctrRep.Next.ResCpu,
					ResMem:    ctrRep.Next.ResMem,
					VolSys:    ctrRep.Next.VolSys,
					VolSysMnt: ctrRep.Next.VolSysMnt,
					Ports:     ctrRep.Next.Ports,
					Options:   ctrRep.Options,
				}

			} else {

				podRep.Replica = inapi.PodOperateReplica{
					RepId:     ctrRep.RepId,
					Node:      ctrRep.Node,
					Action:    ctrRep.Action,
					ResCpu:    ctrRep.ResCpu,
					ResMem:    ctrRep.ResMem,
					VolSys:    ctrRep.VolSys,
					VolSysMnt: ctrRep.VolSysMnt,
					Ports:     ctrRep.Ports,
					Options:   ctrRep.Options,
					Next:      ctrRep.Next,
				}
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
		req.Meta.Id,
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
	mainNodes := []string{}
	for i, v := range status.ZoneMasterList.Items {

		if v.Addr == addr_prev {

			status.ZoneMasterList.Items[i].Addr = host.Spec.PeerLanAddr

			hlog.Printf("warn", "zm status.ZoneMasterList.Items %s->%s",
				addr_prev, host.Spec.PeerLanAddr)
		}

		mainNodes = inapi.ArrayStringUniJoin(mainNodes, status.ZoneMasterList.Items[i].Addr)
	}
	if len(mainNodes) > 0 {
		config.Config.Zone.MainNodes = mainNodes
		config.Config.Flush()
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
	if status.Zone != nil {

		for i, p := range status.Zone.LanAddrs {

			if addr_prev == p {

				status.Zone.LanAddrs[i] = host.Spec.PeerLanAddr

				hlog.Printf("warn", "zm GlobalSysZone2 %s->%s",
					addr_prev, host.Spec.PeerLanAddr)

				status.Zone.Meta.Updated = uint64(types.MetaTimeNow())

				// TOPO
				if rs := data.DataGlobal.NewWriter(
					inapi.NsGlobalSysZone(status.ZoneId), status.Zone).Commit(); rs.OK() {
					data.DataZone.NewWriter(
						inapi.NsZoneSysZone(status.ZoneId), status.Zone).Commit()
				}

				break
			}
		}
	}

	if rs := data.DataZone.NewReader(
		inapi.NsZoneSysMasterNode(status.ZoneId, host.Meta.Id)).Query(); rs.OK() {

		var obj inapi.ResZoneMasterNode
		if err := rs.Decode(&obj); err == nil {

			if obj.Addr == addr_prev {

				data.DataZone.NewWriter(inapi.NsZoneSysMasterNode(status.ZoneId, host.Meta.Id), inapi.ResZoneMasterNode{
					Id:     host.Meta.Id,
					Addr:   host.Spec.PeerLanAddr,
					Action: 1,
				}).Commit()

				hlog.Printf("warn", "zm NsZoneSysMasterNode %s->%s",
					addr_prev, host.Spec.PeerLanAddr)
			}
		}
	}

	hlog.Printf("info", "zm/host/addr %s->%s", addr_prev, host.Spec.PeerLanAddr)
}
