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

package data

func dataUpgrade2() {

	/**
	{ // load domain list
		var (
			offset = inapi.NsGlobalResInstance("domain/")
			rs2    = DataGlobal.NewRanger(offset, offset).
				SetLimit(1000).Exec() // TODO
		)

		for _, v := range rs2.Items {
			var inst inapi.Resource
			if err := v.JsonDecode(&inst); err != nil {
				continue
			}

			domain := &inapi2.GatewayService_Domain{
				Meta: &inapi2.Common_Meta{
					Id:      inst.Meta.ID,
					Name:    inst.Meta.Name,
					User:    inst.Meta.User,
					Created: int64(inst.Meta.Created),
					Updated: time.Now().UnixMilli(),
				},
				ZoneId: inst.Operate.ZoneId,
			}

			if inst.Action == "ok" {
				domain.Action = "start"
			} else {
				domain.Action = "stop"
			}

			if strings.HasPrefix(domain.Meta.Name, "domain/") {
				domain.Meta.Name = domain.Meta.Name[len("domain/"):]
			}

			for _, opt := range inst.Options {
				domain.Options = append(domain.Options, &inapi2.Common_Option{
					Name:  opt.Name,
					Value: opt.Value,
				})
			}

			for _, b := range inst.Bounds {

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

				p := lynkapi.SlicesSearchFunc(domain.Routes, func(a *inapi2.GatewayService_Domain_Route) bool {
					return a.Path == path
				})
				if p == nil {
					p = &inapi2.GatewayService_Domain_Route{
						Path: path,
					}
					domain.Routes = append(domain.Routes, p)
				}

				switch b.Action {
				case 1:
					p.Action = "start"

				case 2:
					p.Action = "stop"

				case 3:
					p.Action = "destroy"
				}

				switch typ {

				case "pod":

					ar := strings.Split(tgt, ":")
					if len(ar) != 2 {
						continue
					}

					podPort, err := strconv.Atoi(ar[1])
					if err != nil || podPort <= 0 || podPort >= 65536 {
						continue
					}

					p.Type = typ
					p.Targets = []string{tgt}

				case "upstream":
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
					p.Type = typ

					addr := fmt.Sprintf("%s:%d", hostIp, hostPort)
					if !slices.Contains(p.Targets, addr) {
						p.Targets = append(p.Targets, addr)
					}

				case "redirect":
					if u, err := url.Parse(tgt); err == nil {
						p.Type = typ
						p.Targets = []string{u.String()}
					}
				}
			}

			DataGlobal.NewWriter(inapi2.NsGlobalGatewayServiceDomain(domain.Meta.Name), domain).
				SetCreateOnly(true).Exec()
			hlog.Printf("info", "data-transfer domain %s", domain.Meta.Name)
		}
	}
	*/
}
