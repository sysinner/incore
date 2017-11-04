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
	"github.com/lessos/lessgo/types"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/auth"
	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var (
	zm_mu sync.Mutex
)

type ApiZoneMaster struct{}

func (s *ApiZoneMaster) HostStatusSync(
	ctx context.Context,
	opts *inapi.ResHost,
) (*inapi.ResZoneMasterList, error) {

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
		return nil, errors.New("BadArgs No Host Found")
	}

	//
	if opts.Spec.PeerLanAddr != "" && opts.Spec.PeerLanAddr != host.Spec.PeerLanAddr {
		zm_host_addr_change(opts, host.Spec.PeerLanAddr)
	}

	//
	if host.SyncStatus(*opts) {
		data.ZoneMaster.PvPut(inapi.NsZoneSysHost(status.ZoneId, opts.Meta.Id), host, nil)
		hlog.Printf("info", "zone-master/host %s updated", opts.Meta.Id)
	}

	tn := uint32(time.Now().Unix())

	for _, v := range opts.Prs {

		path := inapi.NsZonePodReplicaStatus(
			status.ZoneId,
			v.Id,
			uint16(v.Rep),
		)

		prev := inapi.PbPodRepStatusSliceGet(status.ZonePodRepStatusSets, v.Id, v.Rep)

		if prev == nil {
			if rs := data.ZoneMaster.PvGet(path); rs.OK() {
				rs.Decode(prev)
			}
		}
		if prev == nil || prev.Id != v.Id {
			continue
		}
		if prev.OpLog == nil {
			prev.OpLog = inapi.NewPbOpLogSets(inapi.NsZonePodOpRepKey(v.Id, uint16(v.Rep)), 0)
		}

		if v.OpLog != nil && v.OpLog.Version >= prev.OpLog.Version {
			for _, vlog := range v.OpLog.Items {
				prev.OpLog.LogSetEntry(vlog)
			}
		}
		v.OpLog = prev.OpLog
		v.Updated = tn

		for _, v2 := range prev.Boxes {
			if v2.Name == "" {
				prev.Boxes = []*inapi.PbPodBoxStatus{}
				break
			}
		}

		changed := false
		status.ZonePodRepStatusSets, changed = inapi.PbPodRepStatusSliceSync(
			status.ZonePodRepStatusSets, v,
		)

		if changed {
			if rs := data.ZoneMaster.PvPut(path, prev, nil); !rs.OK() {
				hlog.Printf("error", "zone-master/pod StatusSync %s/%d SET Failed %s",
					v.Id, v.Rep, rs.Bytex().String())
				return nil, errors.New("Server Error")
			}
		}

		// hlog.Printf("info", "zone-master/pod StatusSync %s/%d phase:%s updated", v.Id, v.Rep, v.Phase)
		if inapi.OpActionAllow(v.Action, inapi.OpActionRunning) ||
			inapi.OpActionAllow(v.Action, inapi.OpActionStopped) ||
			inapi.OpActionAllow(v.Action, inapi.OpActionDestroyed) {

			bp_key := inapi.NsZoneHostBoundPod(status.ZoneId, opts.Meta.Id, v.Id, uint16(v.Rep))

			if rs := data.ZoneMaster.PvGet(bp_key); rs.OK() {
				var bpod inapi.Pod
				err := rs.Decode(&bpod)

				if err == nil && bpod.Meta.ID == v.Id {
					synced := false

					if inapi.OpActionAllow(v.Action, inapi.OpActionRunning) {
						if inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionStart) &&
							!inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionRunning) {
							bpod.Operate.Action = bpod.Operate.Action | inapi.OpActionRunning
							synced = true
						}
					} else if inapi.OpActionAllow(v.Action, inapi.OpActionStopped) {
						if inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionStop) &&
							!inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionStopped) {
							bpod.Operate.Action = bpod.Operate.Action | inapi.OpActionStopped
							synced = true
						}
					} else if inapi.OpActionAllow(v.Action, inapi.OpActionDestroyed) {
						if inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionDestroy) &&
							!inapi.OpActionAllow(bpod.Operate.Action, inapi.OpActionDestroyed) {
							bpod.Operate.Action = bpod.Operate.Action | inapi.OpActionDestroyed
							synced = true
						}
					}

					if synced {
						bpod.Meta.Updated = types.MetaTimeNow()
						data.ZoneMaster.PvPut(bp_key, bpod, nil)
						hlog.Printf("info", "zone-master/rpc-server sync pod:%s action:%s",
							bpod.Meta.ID, inapi.OpActionStrings(bpod.Operate.Action))
					}
				}
			}
		}
	}

	// hlog.Printf("info", "zone-master/rpc-server hostlet synced pods:%d", len(opts.Prs))

	return &status.ZoneMasterList, nil
}

func zm_host_addr_change(host *inapi.ResHost, addr_prev string) {

	zm_mu.Lock()
	defer zm_mu.Unlock()

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

	if rs := data.ZoneMaster.PvGet(inapi.NsGlobalSysZone(status.ZoneId)); rs.OK() {

		var zone inapi.ResZone
		if err := rs.Decode(&zone); err == nil {

			for i, p := range zone.LanAddrs {

				if addr_prev == p {

					zone.LanAddrs[i] = host.Spec.PeerLanAddr

					hlog.Printf("warn", "ZoneMaster NsGlobalSysZone %s->%s",
						addr_prev, host.Spec.PeerLanAddr)

					data.ZoneMaster.PvPut(inapi.NsGlobalSysZone(status.ZoneId), zone, nil)
					data.ZoneMaster.PvPut(inapi.NsZoneSysInfo(status.ZoneId), zone, nil)

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
