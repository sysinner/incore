// Copyright 2015 Eryx <evorui аt gmail dοt com>, All rights reserved.
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

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hooto/hflag4g/hflag"
	"github.com/sysinner/incore/inconf"
	"github.com/sysinner/incore/inutils/tplrender"
)

var (
	podCfr *inconf.PodConfigurator
	err    error
)

func podSetup() error {

	if podCfr == nil {
		if podCfr, err = inconf.NewPodConfigurator(); err != nil {
			return err
		}
	}

	return nil
}

func appSetup(appSpec string) (*inconf.AppConfigurator, error) {

	if err := podSetup(); err != nil {
		return nil, err
	}

	appCfr := podCfr.AppConfigurator(appSpec)
	if appCfr == nil {
		return nil, errors.New("--app-spec " + appSpec + " not found")
	}

	return appCfr, nil
}

func keyenc(k string) string {
	return strings.Replace(strings.Replace(k, "/", "__", -1), "-", "_", -1)
}

func varParams(appCfr *inconf.AppConfigurator) map[string]interface{} {

	sets := map[string]interface{}{}

	hflag.Each(func(key, val string) {
		if strings.HasPrefix(key, "var/") ||
			strings.HasPrefix(key, "var__") {
			sets[keyenc(key)] = val
		}
	})

	if podCfr != nil {
		sets["pod__replica__rep_id"] = fmt.Sprintf("%d", podCfr.Pod.Replica.RepId)
		sets["pod__operate__replica_cap"] = fmt.Sprintf("%d", podCfr.Pod.Operate.ReplicaCap)
	}

	if appCfr != nil {

		for _, op := range appCfr.App.Operate.Options {
			for _, item := range op.Items {
				var (
					ckey = keyenc(fmt.Sprintf("%s__%s", op.Name, item.Name))
					key  = keyenc(fmt.Sprintf("app__%s__option__%s", appCfr.AppSpecId, ckey))
				)
				sets[key] = item.Value
				if _, ok := sets[ckey]; !ok {
					sets[ckey] = item.Value
				}
			}
		}

		for _, p := range appCfr.App.Operate.Services {

			if p.Name == "" || len(p.Endpoints) < 1 {
				continue
			}

			key := keyenc(fmt.Sprintf("pod__oprep__port__%s__",
				p.Name,
			))
			sets[key+"lan_addr"] = p.Endpoints[0].Ip
			sets[key+"host_port"] = fmt.Sprintf("%d", p.Endpoints[0].Port)

			key = keyenc(fmt.Sprintf("app/service/%s/vpc_addr", p.Name))
			if p.Endpoints[0].VpcIpv4 != "" {
				sets[key] = fmt.Sprintf("%s:%d", p.Endpoints[0].VpcIpv4, p.Port)
			} else {
				sets[key] = ""
			}
		}
	}

	return sets
}

func varRender(txt string, sets map[string]interface{}) ([]byte, error) {
	return tplrender.Render(txt, sets)
}
