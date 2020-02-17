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

package injob

import (
	"fmt"
	"testing"
	"time"
)

type TestJob struct{}

func (it *TestJob) Name() string {
	return "test-job"
}

func (it *TestJob) Run(ctx *Context) error {
	fmt.Println("demojob run at", time.Now().Unix())
	return nil
}

func Test_Schedule_EveryTimeCycle(t *testing.T) {

	for i, v := range [][]int{
		{Second, 10, 3600, 360},
		{Minute, 10, 3600, 6},
		{Hour, 2, 86400, 12},
		{Day, 2, 864000, 5},
		{Month, 2, (86400 * 31 * 4), 2},
	} {

		var (
			sch = NewSchedule().EveryTimeCycle(v[0], uint(v[1]))
			tn  = time.Now()
			hit = 0
		)

		for i := 0; i < v[2]; i++ {
			tn = tn.Add(time.Second)
			if sch.Hit(scheduleTime(tn)) {
				hit += 1
			}
		}

		if hit != v[3] {
			t.Fatalf("Failed Test Schedule_EveryTimeCycle #%d", i)
		}
	}
}

func Test_Schedule_EveryTime(t *testing.T) {

	for i, v := range [][]int{
		{Second, 0, 3600, 60},
		{Minute, 0, 7200, 2},
		{Hour, 2, 86400, 1},
		{Day, 10, 86400 * 31, 1},
		{Month, 10, (86400 * 365), 1},
		{Weekday, 1, (86400 * 14), 2},
	} {

		var (
			sch = NewSchedule().EveryTime(v[0], uint(v[1]))
			tn  = time.Now()
			hit = 0
		)

		for i := 0; i < v[2]; i++ {
			tn = tn.Add(time.Second)
			if sch.Hit(scheduleTime(tn)) {
				hit += 1
			}
		}

		if hit != v[3] {
			t.Fatalf("Failed Test Schedule_EveryTime #%d", i)
		}
	}
}

func Benchmark_Schedule_EveryTimeCycle(b *testing.B) {

	var (
		sch = NewSchedule().EveryTimeCycle(Second, 1)
		tn  = time.Now()
	)

	for i := 0; i < b.N; i++ {
		tn = tn.Add(time.Second)
		sch.Hit(scheduleTime(tn))
	}
}

func Benchmark_Schedule_EveryTime(b *testing.B) {

	var (
		sch = NewSchedule().EveryTime(Weekday, 1)
		tn  = time.Now()
	)

	for i := 0; i < b.N; i++ {
		tn = tn.Add(time.Second)
		sch.Hit(scheduleTime(tn))
	}
}
