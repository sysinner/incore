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

package zonelet

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/lynkdb/lynkapi/go/lynkapi"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"

	inapi2 "github.com/sysinner/incore/v2/inapi"
)

type ZoneletService struct {
}

func (it *ZoneletService) GatewayDomainDeployList(
	ctx lynkapi.Context,
	req *inapi2.GatewayService_DomainDeployListRequest,
) (*inapi2.GatewayService_DomainDeployListResponse, error) {

	rsp := &inapi2.GatewayService_DomainDeployListResponse{
		Version: 1,
	}

	if !status.IsZoneMaster() {
		return nil, lynkapi.NewClientError("Invalid Zone MainNode Address")
	}

	if req.ZoneId == "" {
		req.ZoneId = config.Config.Zone.ZoneId
	}

	var (
		domains []*inapi2.GatewayService_Domain
		pods    = map[string]*inapi.Pod{}
	)

	{ // load domain list
		var (
			offset = inapi2.NsGlobalGatewayServiceDomain("")
			rs     = data.DataGlobal.NewRanger(offset, offset).
				SetLimit(10000).Exec() // TODO
		)

		for _, v := range rs.Items {
			var item inapi2.GatewayService_Domain
			if err := v.JsonDecode(&item); err != nil {
				continue
			}

			if item.ZoneId != config.Config.Zone.ZoneId {
				continue
			}

			if item.Action != "start" || len(item.Routes) == 0 {
				continue
			}

			domains = append(domains, &item)
		}
	}

	if len(domains) == 0 {
		return rsp, nil
	}

	{ // load pod list
		rs := data.DataZone.NewRanger(
			inapi.NsZonePodInstance(config.Config.Zone.ZoneId, ""),
			inapi.NsZonePodInstance(config.Config.Zone.ZoneId, "")).
			SetLimit(10000).Exec()

		for _, v := range rs.Items {

			var pod inapi.Pod
			if err := v.JsonDecode(&pod); err != nil {
				continue
			}

			if pod.Spec.Zone != config.Config.Zone.ZoneId {
				continue
			}

			pods[pod.Meta.ID] = &pod
		}
	}

	for _, domain := range domains {

		if req.Version > 0 && req.Version >= uint64(domain.Meta.Updated) {
			continue
		}

		deploy := &inapi2.GatewayService_DomainDeploy{
			Name:    domain.Meta.Name,
			Version: uint64(domain.Meta.Updated),
		}

		for _, route := range domain.Routes {

			if len(route.Targets) == 0 || route.Action != "start" {
				continue
			}

			p := lynkapi.SlicesSearchFunc(deploy.Routes, func(a *inapi2.GatewayService_DomainDeploy_Route) bool {
				return route.Path == a.Path
			})
			add := false

			if p == nil {
				p = &inapi2.GatewayService_DomainDeploy_Route{
					Path: route.Path,
				}
				add = true
			} else {
				p.Targets = nil
			}

			switch route.Type {
			case "pod":

				ar := strings.Split(route.Targets[0], ":")
				pod, ok := pods[ar[0]]
				if !ok || len(pod.Operate.Replicas) == 0 ||
					!inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStart) {
					continue
				}

				podPort, err := strconv.Atoi(ar[1])
				if err != nil || podPort <= 0 || podPort >= 65536 {
					continue
				}

				for _, rep := range pod.Operate.Replicas {

					if !inapi.OpActionAllow(rep.Action, inapi.OpActionStart) {
						continue
					}

					host := status.GlobalHostList.Item(rep.Node)
					if host == nil {
						continue
					}

					var (
						hostIp   = ""
						hostPort = 0
					)

					if i := strings.IndexByte(host.Spec.PeerLanAddr, ':'); i > 0 {
						hostIp = host.Spec.PeerLanAddr[:i]
					} else {
						hostIp = host.Spec.PeerLanAddr
					}

					if port := lynkapi.SlicesSearchFunc(rep.Ports, func(a *inapi.ServicePort) bool {
						return a.BoxPort == uint16(podPort)
					}); port != nil {
						hostPort = int(port.HostPort)
					} else {
						continue
					}

					addr := fmt.Sprintf("%s:%d", hostIp, hostPort)
					if !slices.Contains(p.Targets, addr) {
						p.Targets = append(p.Targets, addr)
					}
				}

			case "upstream":
				for _, tgt := range route.Targets {
					ar := strings.Split(tgt, ":")
					if len(ar) != 2 {
						continue
					}

					var (
						hostIp   = ""
						hostPort = 0
					)

					if ip := net.ParseIP(ar[0]); len(ip) >= 4 {
						hostIp = ip.String()
					}
					if v, err := strconv.Atoi(ar[1]); err == nil && v > 0 && v < 65536 {
						hostPort = int(v)
					} else {
						continue
					}
					addr := fmt.Sprintf("%s:%d", hostIp, hostPort)
					if !slices.Contains(p.Targets, addr) {
						p.Targets = append(p.Targets, addr)
					}
				}

			case "redirect":
				for _, tgt := range route.Targets {
					if u, err := url.Parse(tgt); err == nil {
						if !slices.Contains(p.Targets, u.String()) {
							p.Targets = append(p.Targets, u.String())
						}
					}
				}
			}

			if len(p.Targets) == 0 {
				continue
			}

			p.Type = route.Type
			if add {
				deploy.Routes = append(deploy.Routes, p)
			}
		}

		if len(deploy.Routes) == 0 {
			continue
		}

		if len(domain.Options) > 0 {
			if opt := lynkapi.SlicesSearchFunc(domain.Options, func(a *inapi2.Common_Option) bool {
				return a.Name == "letsencrypt_enable"
			}); opt != nil && opt.Value == "on" {
				deploy.LetsencryptEnable = true
			}
		}

		rsp.Domains = append(rsp.Domains, deploy)
	}

	return rsp, nil
}
