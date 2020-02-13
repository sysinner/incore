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

package job

import (
	"time"
)

type ScheduleOption uint32

const (
	Second ScheduleOption = 1 << iota // Second
	Minute                            // Minute
	Hour                              // Hour
	Dom                               // Day of month
	Month                             // Month
	Dow                               // Day of week
)

var (
	scheduleStdFields = [6]schedulerFieldType{
		{Second, 0, 59}, // second (0 - 59)
		{Minute, 0, 59}, // minute (0 - 59)
		{Hour, 0, 23},   // hour (0 - 23)
		{Dom, 1, 31},    // day of month (1 - 31)
		{Month, 1, 12},  // month (1 - 12)
		{Dow, 0, 6},     // day of week (0 - 6) (Sunday=0)
	}
)

type schedulerFieldType struct {
	typ ScheduleOption
	min uint
	max uint
}

type Schedule struct {
	times [6]uint64
}

func scheduleTime(t time.Time) [6]uint64 {
	return [6]uint64{
		1 << t.Second(),
		1 << t.Minute(),
		1 << t.Hour(),
		1 << t.Day(),
		1 << uint(t.Month()),
		1 << t.Weekday(),
	}
}

func NewSchedule() *Schedule {

	sch := &Schedule{
		times: [6]uint64{0, 0, 0, 0, 0, 0},
	}

	return sch
}

func (it *Schedule) EveryTime(opt ScheduleOption, in uint) *Schedule {

	i := 0

	for ; i < len(scheduleStdFields); i++ {

		v := scheduleStdFields[i]

		if v.typ == opt {
			break
		}

		it.times[i] = (1 << v.min)
	}

	if i < len(scheduleStdFields) {

		v := scheduleStdFields[i]

		if in < 1 {
			in = 1
		} else if in > v.max {
			in = v.max
		}

		fv := uint64(0)
		for j := v.min; j <= v.max; j += in {
			fv = fv | (1 << j)
		}

		it.times[i] = fv
		i++
	}

	for ; i < len(scheduleStdFields); i++ {

		v := scheduleStdFields[i]

		fv := uint64(0)
		for j := v.min; j <= v.max; j++ {
			fv = fv | (1 << j)
		}

		it.times[i] = fv
	}

	if opt == Dow {

		for i, _ := range []int{3, 4} {

			v := scheduleStdFields[i]

			fv := uint64(0)
			for j := v.min; j <= v.max; j++ {
				fv = fv | (1 << j)
			}

			it.times[i] = fv
		}
	}

	return it
}

func (it *Schedule) Hit(times [6]uint64) bool {
	hit := 0
	for i, v := range it.times {
		if !u64Allow(v, times[i]) {
			break
		}
		hit += 1
	}
	return hit == len(scheduleStdFields)
}
