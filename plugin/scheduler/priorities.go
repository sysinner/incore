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
	"errors"
	"sort"
)

// prioritizer is a priority function that favors hosts with fewer requested resources.
func prioritizer(hosts []*hostFit) (host_priority_list, error) {

	ls := host_priority_list{}

	if len(hosts) < 1 {
		return ls, errors.New("No Host Found")
	}

	for _, host := range hosts {
		ls = append(ls, calculate_occupancy(host))
	}

	sort.Sort(ls)

	return ls, nil
}

// Calculate the occupancy on a host
func calculate_occupancy(host *hostFit) host_priority {

	var (
		cpu_pused = calculate_percentage(host.cpu_used, host.cpu_total)
		mem_pused = calculate_percentage(host.mem_used, host.mem_total)
	)

	return host_priority{
		id:    host.id,
		score: (cpu_pused + mem_pused) / 2,
	}
}

func calculate_percentage(numerator, denominator int32) int {

	if denominator <= 0 {
		return 0
	}

	return int((numerator * 100) / denominator)
}
