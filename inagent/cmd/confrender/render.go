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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/hooto/hflag4g/hflag"
	"github.com/lessos/lessgo/encoding/json"

	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils/filerender"
)

var (
	pod_inst_json = "/home/action/.sysinner/pod_instance.json"
	pod           inapi.PodRep
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

func nsz_entry(id string) *inapi.NsPodServiceMap {
	var nsz inapi.NsPodServiceMap
	if err := json.DecodeFile("/dev/shm/sysinner/nsz/"+id, &nsz); err != nil {
		return nil
	}
	return &nsz
}

func cfgRender(src, dst string) error {

	sets := map[string]string{}

	hflag.Each(func(key, val string) {
		if strings.HasPrefix(key, "var__") {
			sets[key] = val
		}
	})

	for _, app := range pod.Apps {
		for _, op := range app.Operate.Options {
			for _, item := range op.Items {
				key := keyenc(fmt.Sprintf("app__%s__option__%s__%s",
					app.Spec.Meta.ID,
					op.Name,
					item.Name,
				))
				sets[key] = item.Value
			}
		}
	}

	if nsz := nsz_entry(pod.Meta.ID); nsz != nil {
		for _, p := range pod.Replica.Ports {
			key := keyenc(fmt.Sprintf("pod__oprep__port__%s__",
				p.Name,
			))
			sets[key+"host_port"] = fmt.Sprintf("%d", p.HostPort)
			sets[key+"lan_addr"] = nsz.GetIp(p.BoxPort)
		}
	}

	return filerender.Render(src, dst, 0644, sets)
}

func pod_init() error {

	if err := json.DecodeFile(pod_inst_json, &pod); err != nil {
		return err
	}

	if pod.Spec == nil ||
		pod.Spec.Box.Resources == nil {
		return errors.New("Not Pod Instance Setup")
	}

	return nil
}
