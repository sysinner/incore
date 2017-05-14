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
	"sync"
	// "github.com/lessos/lessgo/types"
)

var (
	service_mu sync.RWMutex
)

// ServicePort represents a network port in a single box(container)
type ServicePort struct {
	// Optional: If specified, this must be a DNS_LABEL.  Each named port
	// in a pod must have a unique name.
	Name string `json:"name,omitempty"`
	// Required: This must be a valid port number, 0 < x < 65536.
	BoxPort uint16 `json:"box_port"`
	// Optional: If specified, this must be a valid port number, 0 < x < 65536.
	HostPort uint16 `json:"host_port,omitempty"`
}

type ServicePorts []*ServicePort

func (ls *ServicePorts) Get(box_port uint16) *ServicePort {

	if box_port == 0 {
		return nil
	}

	service_mu.RLock()
	defer service_mu.RUnlock()

	for _, v := range *ls {

		if v.BoxPort == box_port {
			return v
		}
	}

	return nil
}

func (ls *ServicePorts) Del(box_port uint16) {

	if box_port == 0 {
		return
	}

	service_mu.Lock()
	defer service_mu.Unlock()

	for i, v := range *ls {

		if v.BoxPort == box_port {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *ServicePorts) Sync(item ServicePort) (changed bool) {

	if item.BoxPort == 0 {
		return false
	}

	service_mu.Lock()
	defer service_mu.Unlock()

	for i, v := range *ls {

		if v.BoxPort != item.BoxPort {
			continue
		}

		if item.Name != "" && v.Name != item.Name {
			(*ls)[i].Name = item.Name
			changed = true
		}

		if item.HostPort > 0 && v.HostPort != item.HostPort {
			(*ls)[i].HostPort = item.HostPort
			changed = true
		}

		return changed
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *ServicePorts) Clean() {

	service_mu.Lock()
	defer service_mu.Unlock()

	if len(*ls) > 0 {
		*ls = []*ServicePort{}
	}
}

func (ls *ServicePorts) Equal(items ServicePorts) bool {

	if len(*ls) != len(items) {
		return false
	}

	service_mu.RLock()
	defer service_mu.RUnlock()

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.BoxPort != v2.BoxPort {
				continue
			}

			if v.Name != v2.Name ||
				v.HostPort != v2.HostPort {
				return false
			}

			hit = true
			break
		}

		if !hit {
			return false
		}
	}

	return true
}
