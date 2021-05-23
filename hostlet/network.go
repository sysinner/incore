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

package hostlet

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/hooto/hlog4g/hlog"

	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	innet "github.com/sysinner/incore/inutils/network"
)

var (
	hostNetworkBridgeCurrent  = ""
	hostNetworkPeerIP         net.IP
	zoneNetworkMap            inapi.ZoneNetworkMap
	zoneNetworkMapUpdateSetup uint64
)

const (
	hostNetworkVxlanIdDefault = 10
)

func hostNetworkRefresh() error {

	if runtime.GOOS == "darwin" {
		return nil
	}

	if incfg.Config.Host.NetworkVpcBridge == "" {
		return nil
	}

	if hostNetworkPeerIP == nil {

		prip := incfg.Config.Host.LanAddr
		if n := strings.IndexByte(prip, ':'); n > 0 {
			prip = prip[:n]
		}

		pip, err := innet.ParsePrivateIP(prip)
		if err != nil {
			return err
		}

		hostNetworkPeerIP = pip
	}

	if hostNetworkBridgeCurrent != incfg.Config.Host.NetworkVpcBridge {

		brip, err := innet.ParsePrivateIP(incfg.Config.Host.NetworkVpcBridge)
		if err != nil {
			return err
		}

		//
		if err = innet.LinkManager.VxlanSetup(brip, hostNetworkVxlanIdDefault,
			hostNetworkPeerIP); err != nil {
			return err
		}

		hlog.Printf("info", "vpc bridge %s setup ok",
			incfg.Config.Host.NetworkVpcBridge)

		hostNetworkBridgeCurrent = incfg.Config.Host.NetworkVpcBridge
	}

	if zoneNetworkMapUpdateSetup < zoneNetworkMap.UpdateVersion {

		next := zoneNetworkMap.UpdateVersion

		for offset := 1; offset+12 <= len(zoneNetworkMap.VpcRouteData); offset += 12 {

			peerIP := net.IPv4(zoneNetworkMap.VpcRouteData[offset],
				zoneNetworkMap.VpcRouteData[offset+1],
				zoneNetworkMap.VpcRouteData[offset+2],
				zoneNetworkMap.VpcRouteData[offset+3])

			if hostNetworkPeerIP.Equal(peerIP) {
				continue
			}

			//
			if err := innet.LinkManager.VxlanForward(
				hostNetworkVxlanIdDefault,
				peerIP,
			); err != nil {
				hlog.Printf("warn", "network vpc vxlan forward to %s error %s",
					peerIP.String(), err.Error())
				return err
			}
			hlog.Printf("warn", "network vpc vxlan forward to %s ok",
				peerIP.String())

			//
			brIP := net.IP(zoneNetworkMap.VpcRouteData[offset+4 : offset+8])
			vpcIP := net.IP(zoneNetworkMap.VpcRouteData[offset+8 : offset+12])
			if err := innet.LinkManager.RouteReplace(vpcIP, brIP); err != nil {
				hlog.Printf("warn", "network vpc route (%s via %s) replace error %s",
					vpcIP.String(), brIP.String(), err.Error())
				return err
			}

			hlog.Printf("warn", "network vpc route (%s via %s) replace ok",
				vpcIP.String(), brIP.String())
		}

		dnsConf := ""
		for ipn, instanceId := range zoneNetworkMap.VpcInstanceData {
			ipb := inutils.Uint32ToBytes(ipn)
			dnsConf += fmt.Sprintf("[[records]]\nname = \"%s.%s\"\nips = [\"%s\"]\n",
				instanceId, incfg.Config.Zone.NetworkDomainName,
				net.IPv4(ipb[0], ipb[1], ipb[2], ipb[3]).String())
		}
		if len(dnsConf) > 10 {
			if err := inutils.FsWrite("/opt/sysinner/indns/etc/conf.d/innerstack.toml",
				[]byte(dnsConf)); err != nil {
				return err
			}
		}

		zoneNetworkMapUpdateSetup = next
	}

	return nil
}
