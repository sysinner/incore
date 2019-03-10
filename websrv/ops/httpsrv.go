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

package ops

import (
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamclient"
	"github.com/sysinner/incore/config"
)

func NewModule() httpsrv.Module {

	module := httpsrv.NewModule("in_ops")

	module.RouteSet(httpsrv.Route{
		Type: httpsrv.RouteTypeBasic,
		Path: "/zonebound/:zone_id",
		Params: map[string]string{
			"controller": "zonebound",
			"action":     "index",
		},
	})

	module.RouteSet(httpsrv.Route{
		Type:       httpsrv.RouteTypeStatic,
		Path:       "~",
		StaticPath: config.Prefix + "/webui/in",
	})

	module.RouteSet(httpsrv.Route{
		Type:       httpsrv.RouteTypeStatic,
		Path:       "-",
		StaticPath: config.Prefix + "/webui/in/ops/tpl",
	})

	module.ControllerRegister(new(Host))
	module.ControllerRegister(new(PodSpec))
	module.ControllerRegister(new(iamclient.Auth))
	module.ControllerRegister(new(Index))
	module.ControllerRegister(new(Zonebound))
	module.ControllerRegister(new(Sys))

	return module
}
