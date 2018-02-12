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

package v1

import (
	"github.com/hooto/httpsrv"
)

func NewModule() httpsrv.Module {

	module := httpsrv.NewModule("in_v1")

	module.RouteSet(httpsrv.Route{
		Type: httpsrv.RouteTypeBasic,
		Path: "/podbound/:pod_id/:pod_controller/:pod_action",
		Params: map[string]string{
			"controller": "podbound",
			"action":     "index",
		},
	})

	module.RouteSet(httpsrv.Route{
		Type: httpsrv.RouteTypeBasic,
		Path: "/zonebound/:zone_id",
		Params: map[string]string{
			"controller": "zonebound",
			"action":     "index",
		},
	})

	module.ControllerRegister(new(PodSpec))
	module.ControllerRegister(new(Pod))
	module.ControllerRegister(new(AppSpec))
	module.ControllerRegister(new(App))
	module.ControllerRegister(new(Host))
	module.ControllerRegister(new(Resource))
	module.ControllerRegister(new(Podbound))
	module.ControllerRegister(new(PodStats))
	module.ControllerRegister(new(Charge))
	module.ControllerRegister(new(Zonebound))

	return module
}
