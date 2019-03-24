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

func (ls *ScheduleHostVolumes) Equal(ls2 []*ScheduleHostVolume) bool {
	if len((*ls)) != len(ls2) {
		return false
	}
	for _, v := range *ls {
		hit := false
		for _, v2 := range ls2 {
			if v2.Name == v.Name {
				if v2.Total != v.Total ||
					v2.Used != v.Used ||
					v2.Attrs != v.Attrs {
					return false
				}
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func (ls *ScheduleHostVolumes) Get(name string) *ScheduleHostVolume {
	for _, v := range *ls {
		if name == v.Name {
			return v
		}
	}
	return nil
}

func (ls *ScheduleHostVolumes) Sync(item *ScheduleHostVolume) {
	for _, v := range *ls {
		if item.Name == v.Name {
			v.Total = item.Total
			v.Used = item.Used
			v.Attrs = item.Attrs
			return
		}
	}
	*ls = append(*ls, item)
}

func (ls *ScheduleHostVolumes) Del(name string) {
	for i, v := range *ls {
		if name == v.Name {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}
