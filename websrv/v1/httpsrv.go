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

func NewModule() *httpsrv.Module {

	mod := httpsrv.NewModule()

	mod.SetRoute(
		"/podbound/:pod_id/:pod_controller/:pod_action",
		map[string]string{
			"controller": "podbound",
			"action":     "index",
		},
	)

	mod.SetRoute(
		"/zonebound/:zone_id",
		map[string]string{
			"controller": "zonebound",
			"action":     "index",
		},
	)

	mod.RegisterController(
		new(Sys),
		new(PodSpec),
		new(PodRep),
		new(Pod),
		new(AppSpec),
		new(App),
		new(Host),
		new(Resource),
		new(Podbound),
		new(PodStats),
		new(Charge),
		new(Zonebound))

	return mod
}
