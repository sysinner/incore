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

package status

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
)

type StatusNetwork struct {
	mu  sync.RWMutex
	rmu sync.RWMutex

	ready bool

	zoneNetworkMap *inapi.ZoneNetworkMap

	vpcInstanceIpNet    string
	vpcInstanceIpv4Addr net.IP
	vpcInstanceIpv4Net  *net.IPNet

	vpcBridgeIpNet    string
	vpcBridgeIpv4Addr net.IP
	vpcBridgeIpv4Net  *net.IPNet

	vpcBridgeToHost map[uint32]string
	vpcSubnetToHost map[uint32]string
	vpcHostMap      map[string]*hostNetwork
}

func newStatusNetwork() StatusNetwork {
	return StatusNetwork{
		vpcHostMap:      map[string]*hostNetwork{},
		vpcSubnetToHost: map[uint32]string{},
		vpcBridgeToHost: map[uint32]string{},
		zoneNetworkMap: &inapi.ZoneNetworkMap{
			UpdateVersion:   0,
			VpcInstanceData: map[uint32]string{},
		},
	}
}

type hostNetwork struct {
	ready    bool
	ips      []byte
	updated  int64
	instance map[uint8]string
}

func newHostNetwork() *hostNetwork {
	return &hostNetwork{
		ips:      make([]byte, 12),
		instance: map[uint8]string{},
	}
}

const (
	NetworkRouteDataVersion1 = 0x01
)

func (it *StatusNetwork) routeRefresh() {
	var (
		routes = make([]byte, 1+len(it.vpcHostMap)*12)
		offset = 1
	)
	routes[0] = NetworkRouteDataVersion1
	for _, v := range it.vpcHostMap {
		copy(routes[offset:offset+12], v.ips)
		offset += 12
	}

	if bytes.Compare(it.zoneNetworkMap.VpcRouteData, routes) != 0 {
		it.zoneNetworkMap.VpcRouteData = routes
		it.zoneNetworkMap.UpdateVersion++
	}
}

func (it *StatusNetwork) ZoneNetworkMap() *inapi.ZoneNetworkMap {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.zoneNetworkMap
}

func (it *StatusNetwork) ZoneSetup(bridgeIpNet, instanceIpNet string) error {

	if bridgeIpNet == "" && instanceIpNet == "" {
		return nil
	}

	it.mu.Lock()
	defer it.mu.Unlock()

	//
	if it.vpcBridgeIpNet != bridgeIpNet {
		ipv4Addr, ipv4Net, err := net.ParseCIDR(bridgeIpNet)
		if err != nil {
			return err
		}
		if _, err := parsePrivateIP(ipv4Addr.String()); err != nil {
			return err
		}
		it.vpcBridgeIpNet = bridgeIpNet
		it.vpcBridgeIpv4Addr = ipv4Addr.To4()
		it.vpcBridgeIpv4Net = ipv4Net
	}

	//
	if it.vpcInstanceIpNet != instanceIpNet {
		ipv4Addr, ipv4Net, err := net.ParseCIDR(instanceIpNet)
		if err != nil {
			return err
		}
		if _, err := parsePrivateIP(ipv4Addr.String()); err != nil {
			return err
		}
		it.vpcInstanceIpNet = instanceIpNet
		it.vpcInstanceIpv4Addr = ipv4Addr.To4()
		it.vpcInstanceIpv4Net = ipv4Net
	}

	return nil
}

func (it *StatusNetwork) HostSetup(hostId, hostPeerIp, bridgeIp, instanceIpNet string) error {

	it.mu.Lock()
	defer it.mu.Unlock()

	host, ok := it.vpcHostMap[hostId]
	if !ok {
		host = newHostNetwork()
		it.vpcHostMap[hostId] = host
	}

	if hostPeerIp == "" || bridgeIp == "" || instanceIpNet == "" {
		host.ready = true
		return nil
	}

	ips := make([]byte, 12)

	//
	if ip, err := parsePrivateIP(hostPeerIp); err != nil {
		return err
	} else {
		copy(ips[0:4], ip)
	}

	//
	if ip, err := parsePrivateIP(bridgeIp); err != nil {
		return err
	} else if ip[3] == 0 {
		return errors.New("range error")
	} else {
		copy(ips[4:8], ip)
	}
	if pHostId, ok := it.vpcBridgeToHost[inutils.BytesToUint32(ips[4:8])]; ok && pHostId != hostId {
		return nil
	}

	//
	if n := strings.IndexByte(instanceIpNet, '/'); n > 0 {
		instanceIpNet = instanceIpNet[:n]
	}
	if ip, err := parsePrivateIP(instanceIpNet); err != nil {
		return err
	} else {
		copy(ips[8:11], ip)
		ips[11] = 0
	}
	if ips[7] != ips[10] {
		return nil
	}
	if pHostId, ok := it.vpcSubnetToHost[inutils.BytesToUint32(ips[8:12])]; ok && pHostId != hostId {
		return nil
	}

	if bytes.Compare(host.ips, ips) != 0 {
		copy(host.ips, ips)
		it.vpcBridgeToHost[inutils.BytesToUint32(ips[4:8])] = hostId
		it.vpcSubnetToHost[inutils.BytesToUint32(ips[8:12])] = hostId
		host.ready = true
		host.updated = time.Now().UnixNano()

		it.routeRefresh()
	}

	return nil
}

func (it *StatusNetwork) Ready(b bool) {

	it.mu.Lock()
	defer it.mu.Unlock()

	if !b ||
		(b && it.vpcBridgeIpv4Net != nil && it.vpcInstanceIpv4Net != nil) {
		it.ready = b
	}
}

type NetworkVPCAlloc func(chg bool, brNet, ipNet string) bool

func (it *StatusNetwork) HostAlloc(hostId string, cb NetworkVPCAlloc) error {

	it.mu.Lock()
	defer it.mu.Unlock()

	if !it.ready {
		return nil // errors.New("zone's network not ready")
	}

	host, ok := it.vpcHostMap[hostId]
	if !ok {
		host = newHostNetwork()
		it.vpcHostMap[hostId] = host
	}

	if !host.ready {
		return errors.New("host's network not ready")
	}

	var (
		ips = make([]byte, 12)
		chg = false
	)
	copy(ips, host.ips)

	// TODO
	if ips[4] == 0 && ips[8] == 0 {

		copy(ips[4:8], it.vpcBridgeIpv4Addr)
		copy(ips[8:11], it.vpcInstanceIpv4Addr)

		ips[11] = 0

		var (
			brID  = uint8(2)
			brMax = uint8(254)
			hit   = false
		)

		for ; brID < brMax; brID++ {

			ips[7] = brID

			if pHostId, ok := it.vpcBridgeToHost[inutils.BytesToUint32(ips[4:8])]; ok && pHostId != hostId {
				continue
			}

			hit = true
			ips[10] = brID
			break
		}

		if !hit {
			return errors.New("host's network not ready (alloc fail)")
		}

		chg = true
	}

	rs := cb(chg,
		fmt.Sprintf("%d.%d.%d.%d", ips[4], ips[5], ips[6], ips[7]),
		fmt.Sprintf("%d.%d.%d.%d/24", ips[8], ips[9], ips[10], ips[11]))

	if chg {
		if rs {
			copy(host.ips, ips)
			host.ready = true
			host.updated = time.Now().UnixNano()

			it.vpcBridgeToHost[inutils.BytesToUint32(ips[4:8])] = hostId
			it.vpcSubnetToHost[inutils.BytesToUint32(ips[8:12])] = hostId
		}
	} else {
		host.ready = true
	}

	return nil
}

func (it *StatusNetwork) InstanceSetup(hostId string,
	podId string, repId uint32, instanceIp string) error {

	if hostId == "" || instanceIp == "" {
		return nil
	}

	instanceId := inapi.PodRepInstanceName(podId, repId)

	it.mu.Lock()
	defer it.mu.Unlock()

	if !it.ready {
		return nil
	}

	//
	ips := make([]byte, 4)

	//
	if ip, err := parsePrivateIP(instanceIp); err != nil {
		return err
	} else if ip[3] < 2 || ip[3] > 253 {
		return errors.New("range error")
	} else {
		copy(ips, ip)
	}

	pHost, ok := it.vpcHostMap[hostId]
	if !ok || !pHost.ready {
		return nil
	}

	if _, ok = pHost.instance[ips[3]]; !ok {
		pHost.instance[ips[3]] = instanceId
	}

	ipk := inutils.BytesToUint32(ips)
	if _, ok = it.zoneNetworkMap.VpcInstanceData[ipk]; !ok {
		it.zoneNetworkMap.VpcInstanceData[ipk] = instanceId
		it.zoneNetworkMap.UpdateVersion++
	}

	return nil
}

func (it *StatusNetwork) InstanceAlloc(hostId, instanceId string, cb NetworkVPCAlloc) error {

	it.mu.Lock()
	defer it.mu.Unlock()

	if !it.ready {
		return nil
	}

	host, ok := it.vpcHostMap[hostId]
	if !ok {
		host = newHostNetwork()
		it.vpcHostMap[hostId] = host
	}

	if !host.ready {
		return errors.New("host's network not ready")
	}

	var (
		ips = make([]byte, 4)
		chg = false
	)
	copy(ips, host.ips[8:12])

	for i, v := range host.instance {
		if instanceId == v {
			ips[3] = i
			cb(chg, "",
				fmt.Sprintf("%d.%d.%d.%d", ips[0], ips[1], ips[2], ips[3]))

			return nil
		}
	}

	// TODO
	var (
		dID  = uint8(2)
		dMax = uint8(254)
		hit  = false
	)

	for ; dID < dMax; dID++ {

		if _, ok := host.instance[dID]; ok {
			continue
		}

		ips[3] = dID
		hit = true
		break
	}

	if !hit {
		return errors.New("host's network not ready (alloc fail)")
	}

	chg = true

	rs := cb(chg, "",
		fmt.Sprintf("%d.%d.%d.%d", ips[0], ips[1], ips[2], ips[3]))

	if chg && rs {

		ipk := inutils.BytesToUint32(ips)
		it.zoneNetworkMap.VpcInstanceData[ipk] = instanceId

		host.instance[ips[3]] = instanceId
		host.updated = time.Now().UnixNano()

		it.zoneNetworkMap.UpdateVersion++
	}

	return nil
}

func parsePrivateIP(ipAddr string) ([]byte, error) {

	// Private IPv4
	// 10.0.0.0 ~ 10.255.255.255
	// 172.16.0.0 ~ 172.31.255.255
	// 192.168.0.0 ~ 192.168.255.255

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, errors.New("invalid ip address")
	}

	ip = ip.To4()

	ipa := int(ip[0])
	ipb := int(ip[1])

	if ipa == 10 ||
		(ipa == 172 && ipb >= 16 && ipb <= 31) ||
		(ipa == 192 && ipb == 168) {
		return ip, nil
	}

	return nil, errors.New("invalid private ip address")
}
