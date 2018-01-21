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

package inapi

import (
	"sync"
)

var (
	ns_pod_service_mu sync.RWMutex
)

func (ls *NsPodServiceMap) Get(port uint16) *NsPodServiceEntry {

	ns_pod_service_mu.RLock()
	defer ns_pod_service_mu.RUnlock()

	for _, vs := range ls.Services {

		if vs.Port == uint32(port) {
			return vs
		}
	}

	return nil
}

func (ls *NsPodServiceMap) GetIp(port uint16) string {

	ns_pod_service_mu.RLock()
	defer ns_pod_service_mu.RUnlock()

	for _, vs := range ls.Services {

		if vs.Port == uint32(port) {
			if len(vs.Items) > 0 {
				return vs.Items[0].Ip
			}
		}
	}

	return "localhost"
}

// func (ls *NsPodServiceMap) Sync(port uint16,
// 	rep uint16, host_ip string, host_port uint16) (changed bool) {

// 	ns_pod_service_mu.Lock()
// 	defer ns_pod_service_mu.Unlock()

// 	// TODO
// 	rep = 0

// 	for i, vs := range ls.Services {

// 		if vs.Port != uint32(port) {
// 			continue
// 		}

// 		for j, prev := range vs.Items {

// 			if prev.Rep != uint32(rep) {
// 				continue
// 			}

// 			if prev.Ip != host_ip || prev.Port != uint32(host_port) {

// 				ls.Services[i].Items[j].Ip = host_ip
// 				ls.Services[i].Items[j].Port = uint32(host_port)

// 				return true
// 			}

// 			return false
// 		}

// 		ls.Services[i].Items = append(ls.Services[i].Items, &NsPodServiceHost{
// 			Rep:  uint32(rep),
// 			Ip:   host_ip,
// 			Port: uint32(host_port),
// 		})

// 		return true
// 	}

// 	ls.Services = append(ls.Services, &NsPodServiceEntry{
// 		Port: uint32(port),
// 		Items: []*NsPodServiceHost{
// 			{
// 				Rep:  uint32(rep),
// 				Ip:   host_ip,
// 				Port: uint32(host_port),
// 			},
// 		},
// 	})

// 	return true
// }
