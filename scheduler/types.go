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

type hostFit struct {
	id        string
	cpu_used  int64
	cpu_total int64
	mem_used  int64
	mem_total int64
}

// host_priority represents the priority of scheduling to a particular host, lower priority is better.
type host_priority struct {
	id    string
	score int
}

type host_priority_list []host_priority

func (h host_priority_list) Len() int {
	return len(h)
}

func (h host_priority_list) Less(i, j int) bool {

	if h[i].score == h[j].score {
		return h[i].id < h[j].id
	}
	return h[i].score < h[j].score
}

func (h host_priority_list) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}
