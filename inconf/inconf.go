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

package inconf

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/sysinner/incore/inapi"
)

const (
	confFilePath = "/home/action/.sysinner/pod_instance.json"
)

type PodConfigurator struct {
	Pod     *inapi.PodRep
	updated int64
}

type AppConfigurator struct {
	AppSpecId string
	App       *inapi.AppInstance
	updated   int64
}

type AppConfigGroup struct {
	opt *inapi.AppOption
}

type AppServicePort = inapi.AppServicePort

func NewPodConfigurator() (*PodConfigurator, error) {

	var inst inapi.PodRep
	if err := json.DecodeFile(confFilePath, &inst); err != nil {
		return nil, err
	}

	if inst.Spec == nil ||
		inst.Spec.Box.Resources == nil {
		return nil, errors.New("Not Pod Instance Setup")
	}

	return &PodConfigurator{
		Pod:     &inst,
		updated: time.Now().UnixNano() / 1e6,
	}, nil
}

func NewAppConfigurator(appSpecId string) (*AppConfigurator, error) {

	if pc, err := NewPodConfigurator(); err == nil {
		if app := pc.AppConfigurator(appSpecId); app != nil {
			return app, nil
		}
	}

	return nil, errors.New("no app-spec " + appSpecId + " found")
}

func (it *PodConfigurator) Update() bool {

	fp, err := os.Open(confFilePath)
	if err != nil {
		return false
	}
	defer fp.Close()

	if st, err := fp.Stat(); err == nil {
		updated := st.ModTime().UnixNano() / 1e6
		if updated != it.updated {
			var inst inapi.PodRep
			if err := json.DecodeFile(confFilePath, &inst); err == nil &&
				inst.Spec != nil && inst.Spec.Box.Resources != nil {
				it.Pod = &inst
				it.updated = updated
				return true
			}
		}
	}

	return false
}

func (it *PodConfigurator) PodSpec() *inapi.PodSpecBound {
	return it.Pod.Spec
}

func (it *PodConfigurator) AppConfigQuery(cfgGroupNames ...string) *AppConfigGroup {

	for _, app := range it.Pod.Apps {

		for _, opt := range app.Operate.Options {

			for _, v := range cfgGroupNames {

				if !prefixMatch(string(opt.Name), v) {
					continue
				}

				return &AppConfigGroup{
					opt: opt,
				}
			}
		}
	}
	return nil
}

func (it *PodConfigurator) AppConfigurator(appSpecId string) *AppConfigurator {

	if appSpecId != "" {

		for _, app := range it.Pod.Apps {

			if !prefixMatch(app.Spec.Meta.ID, appSpecId) &&
				appSpecId != app.Spec.Meta.ID {
				continue
			}

			return &AppConfigurator{
				AppSpecId: app.Spec.Meta.ID,
				App:       app,
				updated:   it.updated,
			}
		}

		for _, app := range it.Pod.Apps {

			if len(app.Spec.Depends) < 1 {
				continue
			}

			for _, dp := range app.Spec.Depends {

				if !prefixMatch(dp.Id, appSpecId) &&
					appSpecId != dp.Id {
					continue
				}

				return &AppConfigurator{
					AppSpecId: app.Spec.Meta.ID,
					App:       app,
					updated:   it.updated,
				}
			}
		}

	} else if len(it.Pod.Apps) > 0 {
		return &AppConfigurator{
			AppSpecId: it.Pod.Apps[0].Spec.Meta.ID,
			App:       it.Pod.Apps[0],
			updated:   it.updated,
		}
	}

	return nil
}

func (it *AppConfigurator) AppSpec() *inapi.AppSpec {
	return &it.App.Spec
}

func (it *AppConfigurator) AppConfigQuery(cfgGroupNames ...string) *AppConfigGroup {

	if len(it.App.Operate.Options) > 0 {
		for _, v := range cfgGroupNames {
			if cfg := it.AppConfig(v); cfg != nil {
				return cfg
			}
		}
	}

	return nil
}

func (it *AppConfigurator) AppConfig(cfgGroupName string) *AppConfigGroup {

	for _, opt := range it.App.Operate.Options {
		if prefixMatch(string(opt.Name), cfgGroupName) {
			return &AppConfigGroup{
				opt: opt,
			}
		}
	}
	return nil
}

func (it *AppConfigurator) AppConfigField(cfgGroupName, cfgItemName string) *inapi.AppOptionField {

	if opt := it.AppConfig(cfgGroupName); opt != nil {
		return opt.opt.Field(cfgItemName)
	}

	return nil
}

func (it *AppConfigurator) AppConfigValue(cfgGroupName, cfgItemName string) types.Bytex {

	if opt := it.AppConfig(cfgGroupName); opt != nil {
		return opt.Value(cfgItemName)
	}

	return types.Bytex{}
}

func (it *AppConfigurator) AppConfigValueOK(cfgGroupName, cfgItemName string) (types.Bytex, bool) {

	if opt := it.AppConfig(cfgGroupName); opt != nil {
		return opt.ValueOK(cfgItemName)
	}

	return types.Bytex{}, false
}

func (it *AppConfigurator) AppServiceQuery(qs ...string) *AppServicePort {

	for _, q := range qs {

		var (
			ar   = strings.Split(q, ";")
			spec = ""
			port = 0
		)

		for _, qv := range ar {

			qvs := strings.Split(qv, "=")
			if len(qvs) != 2 {
				continue
			}

			switch qvs[0] {

			case "spec":
				spec = qvs[1]

			case "port":
				port, _ = strconv.Atoi(qvs[1])
			}
		}

		if srv := it.AppService(spec, uint32(port)); srv != nil {
			return srv
		}
	}

	return nil
}

func (it *AppConfigurator) AppService(srvAppSpecId string, port uint32) *AppServicePort {

	if len(it.App.Operate.Services) > 0 {

		for _, v := range it.App.Operate.Services {

			if port > 0 && v.Port != port {
				continue
			}

			if len(v.Endpoints) < 1 {
				continue
			}

			if srvAppSpecId != "" &&
				!prefixMatch(v.Spec, srvAppSpecId) &&
				srvAppSpecId != v.Spec {
				continue
			}

			return v
		}
	}

	return nil
}

func (it *AppConfigGroup) Value(itemName string) types.Bytex {
	return it.opt.Value(itemName)
}

func (it *AppConfigGroup) ValueOK(itemName string) (types.Bytex, bool) {
	return it.opt.ValueOK(itemName)
}

func prefixMatch(s1, s2 string) bool {
	if len(s1) > 0 && s1 == s2 {
		return true
	} else if len(s2) > 1 && s2[len(s2)-1] == '*' {
		if strings.HasPrefix(s1, s2[:len(s2)-1]) {
			return true
		}
	}
	return false
}
