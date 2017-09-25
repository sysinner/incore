// Copyright 2015 Authors, All rights reserved.
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

package losapi

import (
	"sort"
	"sync"
	"time"

	"github.com/lessos/lessgo/types"
)

var (
	cycles = []uint32{
		86400, 3600, 1800, 1200, 900, 600, 300, 120,
		60, 30, 20, 15, 10, 5, 3, 1,
	}
	cycles_qry = []uint32{
		86400, 3600, 1800, 1200, 900, 600, 300, 120,
		60,
	}
)

type TimeStatsFeedQuerySet struct {
	TimeCycle uint32                    `json:"tc,omitempty"`
	TimePast  uint32                    `json:"tp,omitempty"`
	TimeStart uint32                    `json:"ts,omitempty"`
	Items     []*TimeStatsEntryQuerySet `json:"is,omitempty"`
}

func (this *TimeStatsFeedQuerySet) Fix() {

	if this.TimePast < 600 {
		this.TimePast = 600
	} else if this.TimePast > (30 * 86400) {
		this.TimePast = (30 * 86400)
	}

	if this.TimeCycle <= 10 {
		this.TimeCycle = 10
	} else if this.TimeCycle >= 86400 {
		this.TimeCycle = 86400
	} else {

		for _, v := range cycles_qry {
			if this.TimeCycle >= v {
				this.TimeCycle = v
				break
			}
		}
	}

	this.TimeStart = uint32(time.Now().UTC().Unix()) - this.TimePast
	t := time.Unix(int64(this.TimeStart), 0)
	if fix := (uint32(t.Hour()*3600) + uint32(t.Minute()*60) + uint32(t.Second())) % this.TimeCycle; fix > 0 {
		this.TimeStart = this.TimeStart - fix
	}
}

type TimeStatsEntryQuerySet struct {
	Name  string `json:"n,omitempty"`
	Delta bool   `json:"d,omitempty"`
}

func (this *TimeStatsFeedQuerySet) Get(name string) *TimeStatsEntryQuerySet {
	for _, v := range this.Items {
		if v.Name == name {
			return v
		}
	}
	return nil
}

//
type TimeStatsFeed struct {
	types.TypeMeta `json:",inline"`
	Cycle          uint32            `json:"cycle,omitempty"`
	Items          []*TimeStatsEntry `json:"items,omitempty"`
	op_mu          sync.RWMutex
}

type TimeStatsEntry struct {
	Name  string                 `json:"name,omitempty"`
	Items []*TimeStatsEntryValue `json:"items,omitempty"`
	op_mu sync.RWMutex
}

type TimeStatsEntryValue struct {
	Time  uint32 `json:"time"`
	Value int64  `json:"value"`
	num   uint32
}

func NewTimeStatsFeed(c uint32) *TimeStatsFeed {
	feed := &TimeStatsFeed{
		Cycle: c,
	}
	feed.cyclefix()
	return feed
}

func (this *TimeStatsFeed) cyclefix() {
	if this.Cycle <= 1 {
		this.Cycle = 1
	} else if this.Cycle >= 86400 {
		this.Cycle = 86400
	} else {

		for _, v := range cycles {
			if this.Cycle >= v {
				this.Cycle = v
				break
			}
		}
	}
}

const (
	timeStatValueMergeAvg       = "avg"
	timeStatValueMergeOverwrite = "ow"
	timeStatValueMergeEx        = "ex"
)

func (this *TimeStatsFeed) Sync(name string, timo uint32, value int64, merge_type string) {

	this.cyclefix()

	t := time.Unix(int64(timo), 0)
	if fix := (uint32(t.Hour()*3600) + uint32(t.Minute()*60) + uint32(t.Second())) % this.Cycle; fix > 0 {
		timo = timo - fix + this.Cycle
	}

	this.op_mu.Lock()
	defer this.op_mu.Unlock()

	for _, v := range this.Items {
		if v.Name == name {
			v.Sync(timo, value, merge_type, false)
			return
		}
	}

	v := &TimeStatsEntry{
		Name: name,
	}
	v.Sync(timo, value, merge_type, false)
	this.Items = append(this.Items, v)
}

func (this *TimeStatsFeed) Get(name string) *TimeStatsEntry {

	this.op_mu.RLock()
	defer this.op_mu.RUnlock()

	for _, v := range this.Items {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (this *TimeStatsFeed) CycleSplit(name string, gs_cycle uint32) (*TimeStatsEntry, uint32) {

	this.cyclefix()
	if gs_cycle < this.Cycle {
		gs_cycle = this.Cycle
	} else if gs_cycle > 3600 {
		gs_cycle = 3600
	}

	gs_cycle = gs_cycle - (gs_cycle % this.Cycle)
	if gs_cycle >= this.Cycle {
		if entry := this.Get(name); entry != nil {
			return entry.cycleSplit(gs_cycle)
		}
	}

	return nil, 0
}

func (this *TimeStatsEntry) lastTime() uint32 {

	if n := len(this.Items); n > 0 {
		return this.Items[n-1].Time
	}
	return 0
}

func (this *TimeStatsEntry) Sync(timo uint32, value int64, merge_type string, force bool) {

	if !force && (value < 1 || timo < this.lastTime()) {
		return
	}

	this.op_mu.Lock()
	defer this.op_mu.Unlock()

	for _, v := range this.Items {

		if v.Time != timo {
			continue
		}

		switch merge_type {
		case timeStatValueMergeOverwrite:
			v.Value = value
			v.num = 1

		case timeStatValueMergeAvg:
			v.Value = ((v.Value * int64(v.num)) + value) / int64(v.num+1)
			v.num++

		case timeStatValueMergeEx:

		default:
		}

		return
	}

	this.Items = append(this.Items, &TimeStatsEntryValue{
		Time:  timo,
		Value: value,
		num:   1,
	})

	if len(this.Items) > 3600 {
		this.Items = this.Items[1800:]
	}
}

func (this *TimeStatsEntry) Sort() {

	this.op_mu.Lock()
	defer this.op_mu.Unlock()

	sort.Slice(this.Items, func(i, j int) bool {
		return this.Items[i].Time < this.Items[j].Time
	})
}

func (this *TimeStatsEntry) cycleSplit(gs_cycle uint32) (*TimeStatsEntry, uint32) {

	this.op_mu.Lock()
	defer this.op_mu.Unlock()

	if len(this.Items) < 1 {
		return nil, 0
	}

	var (
		gs_time_cr = this.Items[0].Time
		t          = time.Unix(int64(gs_time_cr), 0)
	)
	if fix := (uint32(t.Minute()*60) + uint32(t.Second())) % gs_cycle; fix > 0 {
		gs_time_cr = gs_time_cr - fix + gs_cycle
	}

	if gs_time_cr >= this.lastTime() {
		return nil, 0
	}

	entry := &TimeStatsEntry{
		Name: this.Name,
	}
	for _, v := range this.Items {

		if v.Time > gs_time_cr {
			break
		}

		entry.Items = append(entry.Items, &TimeStatsEntryValue{
			Time:  v.Time,
			Value: v.Value,
		})
	}
	if len(entry.Items) < 1 {
		return nil, 0
	}

	if len(entry.Items) >= len(this.Items) {
		this.Items = []*TimeStatsEntryValue{}
	} else {
		this.Items = this.Items[len(entry.Items):]
	}

	return entry, gs_time_cr
}
