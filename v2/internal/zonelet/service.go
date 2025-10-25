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
	"path/filepath"
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
		appDomains = map[string][]*inapi.Resource{}
		domains    = map[string]*inapi.Resource{}
		pods       = map[string]*inapi.Pod{}
	)

	{ // load domain list
		var (
			offset = inapi.NsGlobalResInstance("domain/")
			rs2    = data.DataGlobal.NewRanger(offset, offset).
				SetLimit(1000).Exec() // TODO
		)

		for _, v := range rs2.Items {
			var inst inapi.Resource
			if err := v.JsonDecode(&inst); err != nil {
				continue
			}
			if inst.Operate.AppId == "" {
				continue
			}

			appDomains[inst.Operate.AppId] = append(appDomains[inst.Operate.AppId], &inst)
		}
	}

	{ // load pod/app list
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
				// !inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStart) {
				continue
			}

			if app := lynkapi.SlicesSearchFunc(pod.Apps, func(a *inapi.AppInstance) bool {
				_, ok := appDomains[a.Meta.ID]
				return ok
			}); app != nil {
				for _, domain := range appDomains[app.Meta.ID] {
					domains[domain.Meta.ID] = domain

					if domain.Operate.ZoneId == "" {
						domain.Operate.ZoneId = config.Config.Zone.ZoneId

						// next upgrade
						key := domain.Meta.Name
						if !strings.HasPrefix(key, "domain/") {
							key = "domain/" + key
						}
						data.DataGlobal.NewWriter(inapi.NsGlobalResInstance(key), domain).Exec()
					}
				}
			}

			pods[pod.Meta.ID] = &pod
		}
	}

	for _, domain := range domains {

		if req.Version > 0 && req.Version >= uint64(domain.Meta.Updated) {
			continue
		}

		gatewayInstance := &inapi2.GatewayService_DomainDeploy{
			Id:      domain.Meta.ID,
			Name:    domain.Meta.Name,
			Version: uint64(domain.Meta.Updated),
		}

		if strings.HasPrefix(gatewayInstance.Name, "domain/") {
			gatewayInstance.Name = gatewayInstance.Name[len("domain/"):]
		}

		for _, b := range domain.Bounds {

			var (
				typ = ""
				tgt = ""
			)

			if i := strings.IndexByte(b.Value, ':'); i > 0 {
				typ = b.Value[:i]
				tgt = b.Value[i+1:]
			} else {
				continue
			}

			path := b.Name
			if strings.HasPrefix(path, "domain/basepath") {
				path = path[len("domain/basepath"):]
			}
			if len(path) == 0 {
				path = "/"
			} else if path[0] != '/' {
				path = "/" + path
			}
			path = filepath.Clean(path)

			p := lynkapi.SlicesSearchFunc(gatewayInstance.Locations, func(a *inapi2.GatewayService_DomainDeploy_Location) bool {
				return a.Path == path
			})
			add := false

			if p == nil {
				p = &inapi2.GatewayService_DomainDeploy_Location{
					Path: path,
				}
				add = true
			}

			switch typ {

			case "pod":

				ar := strings.Split(tgt, ":")
				if len(ar) != 2 {
					continue
				}

				pod, ok := pods[ar[0]]
				if !ok || len(pod.Operate.Replicas) == 0 {
					continue
				}

				p.Type = typ

				podPort, err := strconv.Atoi(ar[1])
				if err != nil || podPort <= 0 || podPort >= 65536 {
					continue
				}

				for _, rep := range pod.Operate.Replicas {

					// if !inapi.OpActionAllow(rep.Action, inapi.OpActionStart) {
					// 	continue
					// }

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
				ar := strings.Split(tgt, ":")
				if len(ar) != 2 {
					continue
				}
				p.Type = typ

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
			case "redirect":
				if u, err := url.Parse(tgt); err == nil {
					p.Type = typ
					p.TargetUrl = u.String()
				}
			}

			if len(p.Targets) == 0 && p.TargetUrl == "" {
				continue
			}

			if add {
				gatewayInstance.Locations = append(gatewayInstance.Locations, p)
			}
		}

		if len(gatewayInstance.Locations) == 0 {
			continue
		}

		if len(domain.Options) > 0 {
			if v, ok := domain.Options.Get("letsencrypt_enable"); ok && v.String() == "on" {
				gatewayInstance.LetsencryptEnable = true
			}
		}

		rsp.Domains = append(rsp.Domains, gatewayInstance)
	}

	return rsp, nil
}
