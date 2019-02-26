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

package scheduler

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	typeScheduler "github.com/sysinner/incore/inapi/scheduler"
)

func TestPriorityList(t *testing.T) {

	ls := host_priority_list{
		{
			id:    "2",
			score: 2,
		},
		{
			id:    "1",
			score: 1,
		},
		{
			id:    "3",
			score: 3,
		},
	}

	sort.Sort(ls)
	if ls[0].id != "1" || ls[1].id != "2" || ls[2].id != "3" {
		t.Fatal("Failed TestPriority")
	}
}

func TestPrioritizer(t *testing.T) {

	fit_hosts := []*hostFit{
		{
			id:        "2",
			cpu_used:  80,
			cpu_total: 160,
			mem_used:  5,
			mem_total: 10,
		},
		{
			id:        "1",
			cpu_used:  10,
			cpu_total: 160,
			mem_used:  1,
			mem_total: 10,
		},
		{
			id:        "3",
			cpu_used:  160,
			cpu_total: 160,
			mem_used:  10,
			mem_total: 10,
		},
	}

	ls, err := prioritizer(fit_hosts)
	if err != nil {
		t.Fatal("Failed TestPriority")
	}

	if ls[0].id != "1" || ls[1].id != "2" || ls[2].id != "3" {
		t.Fatal("Failed TestPriority")
	}
}

var (
	hosts typeScheduler.ScheduleHostList
)

func bench_init() {

	if len(hosts.Items) > 0 {
		return
	}

	// 5000 hosts in one zone-master
	for i := 0; i < 5000; i++ {

		hosts.Items = append(hosts.Items, &typeScheduler.ScheduleHostItem{
			Id:               fmt.Sprintf("%d", i),
			CellId:           "general",
			OpAction:         1,
			CpuTotal:         320,
			CpuUsed:          int32(rand.Int63n(160)),
			MemTotal:         64 * 1024,
			MemUsed:          int32(rand.Int63n(32)),
			BoxDockerVersion: "1.0.0",
		})
	}
}

func Benchmark_Schedule(b *testing.B) {

	bench_init()

	scheduler_bench := NewScheduler()

	spec := &typeScheduler.SchedulePodSpec{
		BoxDriver: "docker",
		CellId:    "general",
	}

	for i := 0; i < b.N; i++ {

		rep := &typeScheduler.SchedulePodReplica{
			RepId: 0,
			Cpu:   int32(rand.Int63n(160)),
			Mem:   int32(rand.Int63n(32)),
		}

		if host, err := scheduler_bench.ScheduleHost(spec, rep, &hosts, nil); err != nil {
			b.Fatalf("Failed Benchmark_Prioritizer %s", err.Error())
		} else if host.Id == "" {
			b.Fatal("Failed Benchmark_Prioritizer")
			// host.CpuUsed += rep.Cpu
			// host.MemUsed += rep.Mem
		}
	}
}
