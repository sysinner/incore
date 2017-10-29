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

	"github.com/sysinner/incore/inapi"
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

	fit_hosts := []*host_fit{
		{
			id:        "2",
			cpu_used:  8000,
			cpu_total: 16000,
			mem_used:  5 * inapi.ByteGB,
			mem_total: 10 * inapi.ByteGB,
		},
		{
			id:        "1",
			cpu_used:  1000,
			cpu_total: 16000,
			mem_used:  1 * inapi.ByteGB,
			mem_total: 10 * inapi.ByteGB,
		},
		{
			id:        "3",
			cpu_used:  16000,
			cpu_total: 16000,
			mem_used:  10 * inapi.ByteGB,
			mem_total: 10 * inapi.ByteGB,
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
	hosts inapi.ResHostList
)

func bench_init() {

	if len(hosts.Items) > 0 {
		return
	}

	// 5000 hosts in one zone-master
	for i := 0; i < 5000; i++ {

		hosts.Items = append(hosts.Items, &inapi.ResHost{
			Meta: &inapi.ObjectMeta{
				Id: fmt.Sprintf("%d", i),
			},
			Operate: &inapi.ResHostOperate{
				Action:  1,
				CpuUsed: rand.Int63n(16000),
				MemUsed: int64(rand.Int63n(32 * int64(inapi.ByteGB))),
			},
			Spec: &inapi.ResHostSpec{
				Capacity: &inapi.ResHostResource{
					Cpu: 32000,
					Mem: uint64(64 * int64(inapi.ByteGB)),
				},
			},
		})
	}
}

func Benchmark_Schedule(b *testing.B) {

	bench_init()

	scheduler_bench := NewScheduler()

	for i := 0; i < b.N; i++ {

		pod := inapi.Pod{
			Spec: &inapi.PodSpecBound{
				Boxes: []inapi.PodSpecBoxBound{
					{
						Resources: &inapi.PodSpecBoxResComputeBound{
							CpuLimit: rand.Int63n(16000),
							MemLimit: rand.Int63n(32 * int64(inapi.ByteGB)),
						},
					},
				},
			},
		}

		if id, err := scheduler_bench.Schedule(pod, hosts); err != nil {
			b.Fatalf("Failed Benchmark_Prioritizer %s", err.Error())
		} else if id == "" {
			b.Fatal("Failed Benchmark_Prioritizer")
		}
	}
}
