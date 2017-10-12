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

package podrunner

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/locker"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	in_sts "github.com/sysinner/incore/status"
)

type BoxKeeper struct {
	mu        sync.Mutex
	instances map[string]*BoxInstance
	inited    bool
	sets      types.ArrayString
	actions   chan string
	hidocker  *docker.Client
	mmu       *locker.HashPool
}

var (
	box_keeper      BoxKeeper
	err             error
	docker_unixsock = "unix:///var/run/docker.sock"
	box_name_pat    = regexp.MustCompile("^([0-9a-f]{16,24})-([0-9a-f]{4})-([a-z]{1}[a-z0-9]{0,19})$")
	cmd_install     = "/usr/bin/install"
)

func init() {

	if path, err := exec.LookPath("install"); err == nil {
		cmd_install = path
	}

	box_keeper = BoxKeeper{
		instances: map[string]*BoxInstance{},
		inited:    false,
		actions:   make(chan string, 1000),
		hidocker:  nil,
		mmu:       locker.NewHashPool(runtime.NumCPU() * 2),
	}

	go box_keeper.status_watcher()
	go box_keeper.stats_watcher()
	go box_keeper.ctr_action()
}

func box_inst_name_parse(hostname string) (pod_id string, rep_id uint16, box_name string) {

	if ns := box_name_pat.FindStringSubmatch(hostname); len(ns) == 4 {

		rb, _ := hex.DecodeString(ns[2])
		rep_id = binary.BigEndian.Uint16(rb)

		return ns[1], rep_id, ns[3]
	}

	return "", 0, ""
}

func (br *BoxKeeper) stats_watcher() {

	var (
		toffset = int64(time.Now().UnixNano()) % stats_tick
	)

	time.Sleep(time.Duration(stats_tick - toffset - 10e6))

	ticker := time.NewTicker(time.Duration(stats_tick))
	defer ticker.Stop()

	for {
		tl := <-ticker.C

		if !br.inited || in_sts.ZoneId == "" ||
			br.hidocker == nil || len(br.instances) > 100 {
			continue
		}

		timo := uint32(tl.UTC().Unix())

		br.mu.Lock()
		for inst_name, vc := range br.instances {

			if vc.stats_pending || len(vc.ID) < 10 {
				continue
			}

			br.instances[inst_name].stats_pending = true

			if vc.Stats == nil {
				br.instances[inst_name].Stats = inapi.NewTimeStatsFeed(stats_cycle_buf)
			}

			go br.stats_watcher_ado(vc.ID, inst_name, timo)
		}
		br.mu.Unlock()
	}
}

func (br *BoxKeeper) stats_watcher_ado(ct_id string, inst_name string, timo uint32) {

	defer func() {
		br.mu.Lock()
		br.instances[inst_name].stats_pending = false
		br.mu.Unlock()
	}()

	var (
		timeout  = 3 * time.Second
		ct_stats = make(chan *docker.Stats, 2)
	)

	if err := br.hidocker.Stats(docker.StatsOptions{
		ID:                ct_id,
		Stats:             ct_stats,
		Stream:            false,
		Timeout:           timeout,
		InactivityTimeout: timeout,
	}); err != nil {
		hlog.Printf("error", "docker.Stats %s error %s", inst_name, err.Error())
		return
	}

	stats, ok := <-ct_stats
	if !ok {
		return
	}

	br.mu.Lock()
	box_inst, ok := br.instances[inst_name]
	br.mu.Unlock()
	if !ok || box_inst == nil || box_inst.Stats == nil {
		return
	}

	// RAM
	box_inst.Stats.Sync("ram/us", timo,
		int64(stats.MemoryStats.Usage), "avg")

	box_inst.Stats.Sync("ram/cc", timo,
		int64(stats.MemoryStats.Stats.Cache), "avg")

	// Networks
	net_io_rs := int64(0)
	net_io_ws := int64(0)
	for _, v := range stats.Networks {
		net_io_rs += int64(v.RxBytes)
		net_io_ws += int64(v.TxBytes)
	}

	box_inst.Stats.Sync("net/rs", timo, net_io_rs, "ow")
	box_inst.Stats.Sync("net/ws", timo, net_io_ws, "ow")

	// CPU
	box_inst.Stats.Sync("cpu/us", timo,
		int64(stats.CPUStats.CPUUsage.TotalUsage), "ow")

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
	box_inst.Stats.Sync("fs/rn", timo, fs_rn, "ow")
	box_inst.Stats.Sync("fs/rs", timo, fs_rs, "ow")
	box_inst.Stats.Sync("fs/wn", timo, fs_wn, "ow")
	box_inst.Stats.Sync("fs/ws", timo, fs_ws, "ow")

	ar := []string{
		"ram/us", "ram/cc",
		"net/rs", "net/ws",
		"cpu/us",
		"fs/rn", "fs/rs", "fs/wn", "fs/ws",
	}
	feed := inapi.NewTimeStatsFeed(stats_cycle_buf)
	feed_tc := uint32(0)
	for _, v := range ar {
		if entry, tc := box_inst.Stats.CycleSplit(v, stats_cycle_log); entry != nil {
			if tc < 1 {
				continue
			}

			feed_tc = tc
			for _, v2 := range entry.Items {
				feed.Sync(v, v2.Time, v2.Value, "ow")
			}
		}
	}

	if feed_tc > 0 {
		in_db.HiMaster.ProgPut(
			inapi.NsZonePodRepStats(
				in_sts.ZoneId,
				box_inst.PodID,
				box_inst.RepId,
				"sys",
				feed_tc,
			),
			skv.NewProgValue(feed),
			&skv.ProgWriteOptions{
				Expired: time.Now().Add(30 * 24 * time.Hour),
			},
		)
		// hlog.Printf("info", "docker.Stats at %d %v",
		// 	feed_tc, time.Unix(int64(feed_tc), 0))
	}
}

func (br *BoxKeeper) ctr_sync(pod *inapi.Pod) {

	br.mu.Lock()
	defer br.mu.Unlock()

	//
	for _, box_spec := range pod.Spec.Boxes {

		inst_name := fmt.Sprintf(
			"%s-%s-%s",
			pod.Meta.ID, inutils.Uint16ToHexString(pod.Operate.Replica.Id), box_spec.Name,
		)

		if len(box_spec.Command) < 1 {
			box_spec.Command = []string{"/home/action/.sysinner/ininit"}
		}

		box, ok := box_keeper.instances[inst_name]
		if !ok {

			box = &BoxInstance{
				ID:          "",
				Name:        inst_name,
				PodOpAction: pod.Operate.Action,
				PodID:       pod.Meta.ID,
				RepId:       pod.Operate.Replica.Id,
				Spec:        box_spec,
				Apps:        pod.Apps,
				Ports:       pod.Operate.Replica.Ports, // TODO
				Stats:       inapi.NewTimeStatsFeed(stats_cycle_buf),
			}

			box_keeper.instances[inst_name] = box

		} else {

			if pod.Operate.Action != box.PodOpAction && pod.Operate.Action > 0 {
				box.PodOpAction = pod.Operate.Action
			}

			if box.Spec.Updated < 1 || box.Spec.Updated != box_spec.Updated {
				box.Spec = box_spec
			}
		}

		/*
			// debug ...
			box.Spec.Ports.Sync(inapi.Port{
				Name:     "http",
				Protocol: inapi.ProtocolTCP,
				BoxPort:  8080,
			})
			box.Spec.Ports.Sync(inapi.Port{
				Name:     "ssh",
				Protocol: inapi.ProtocolTCP,
				BoxPort:  22,
			})
		*/

		// TODO destroy bound apps
		if pod.Apps != nil {

			if box.Apps == nil {
				box.Apps = pod.Apps
			} else {

				for _, a := range pod.Apps {
					box.Apps.Sync(a)
				}
			}
		}

		if !box.Ports.Equal(pod.Operate.Replica.Ports) {
			box.Ports = pod.Operate.Replica.Ports
		}

		box.volume_mounts_refresh()

		if len(br.actions) < 100 {
			br.actions <- inst_name
		}
	}

	// hlog.Printf("info", "nodelet/box CtrSync POD:%s", pod.Meta.ID)
}

func (br *BoxKeeper) status_update(item *BoxInstance) {

	br.mu.Lock()

	// hlog.Printf("info", "nodelet/box status_update POD:%s", item.PodID)

	if inst, ok := box_keeper.instances[item.Name]; ok {

		inst.Status.Sync(item.Status)

		if inst.PodOpAction != item.PodOpAction && item.PodOpAction > 0 {
			inst.PodOpAction = item.PodOpAction
		}

		if item.Status.Phase == inapi.OpStatusDestroyed {
			inst.ID, item.ID = "", ""
		} else if item.ID != "" {
			inst.ID = item.ID
		}

	} else {
		box_keeper.instances[item.Name] = item
	}

	br.mu.Unlock()

	pod_status_sync(inapi.NsZonePodOpRepKey(item.PodID, item.RepId))
}

func (br *BoxKeeper) ctr_action() {

	for inst_name := range br.actions {

		go func(inst_name string) {

			br.mmu.Lock([]byte(inst_name))
			defer br.mmu.Unlock([]byte(inst_name))

			br.run(inst_name)

			// if err := br.run(inst_name); err != nil {
			// 	hlog.Printf("error", "nodelet/box ctr_action err:%s %s", inst_name, err.Error())
			// }
		}(inst_name)
	}
}
