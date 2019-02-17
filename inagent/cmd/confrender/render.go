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

package confrender

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hooto/hflag4g/hflag"

	"github.com/sysinner/incore/inconf"
	"github.com/sysinner/incore/inutils/filerender"
)

var (
	podCfr  *inconf.PodConfigurator
	appCfr  *inconf.AppConfigurator
	appSpec = ""
	err     error
)

func ActionConfig() error {

	if err := pod_init(); err != nil {
		return err
	}

	if v, ok := hflag.ValueOK("in"); ok {
		if v2, ok2 := hflag.ValueOK("out"); ok2 {
			if err := cfgRender(v.String(), v2.String()); err != nil {
				return err
			} else {
				return nil
			}
		}
	}

	return errors.New("invalid command")
}

func keyenc(k string) string {
	return strings.Replace(strings.Replace(k, "/", "__", -1), "-", "_", -1)
}

func cfgRender(src, dst string) error {

	sets := map[string]interface{}{}

	hflag.Each(func(key, val string) {
		if strings.HasPrefix(key, "var__") {
			sets[key] = val
		}
	})

	for _, op := range appCfr.App.Operate.Options {
		for _, item := range op.Items {
			key := keyenc(fmt.Sprintf("app__%s__option__%s__%s",
				appCfr.AppSpecId,
				op.Name,
				item.Name,
			))
			sets[key] = item.Value
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
	}

	return filerender.Render(src, dst, 0644, sets)
}

func pod_init() error {

	if podCfr, err = inconf.NewPodConfigurator(); err != nil {
		return err
	}

	if v, ok := hflag.ValueOK("app-spec"); ok {
		appSpec = v.String()
	}

	appCfr = podCfr.AppConfigurator(appSpec)
	if appCfr == nil {
		return errors.New("No AppSpec (" + appSpec + ") Found")
	}

	return nil
}
