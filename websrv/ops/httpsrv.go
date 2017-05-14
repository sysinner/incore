// Copyright 2015 Authors, All rights reserved.
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
	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lessos/loscore/config"
	"github.com/lessos/lessgo/httpsrv"
)

func NewModule() httpsrv.Module {

	module := httpsrv.NewModule("los_ops")

	module.RouteSet(httpsrv.Route{
		Type:       httpsrv.RouteTypeStatic,
		Path:       "~",
		StaticPath: config.Prefix + "/webui/los",
	})

	module.RouteSet(httpsrv.Route{
		Type:       httpsrv.RouteTypeStatic,
		Path:       "-",
		StaticPath: config.Prefix + "/webui/los/ops/tpl",
	})

	module.ControllerRegister(new(Host))
	module.ControllerRegister(new(iamclient.Auth))
	module.ControllerRegister(new(Index))

	return module
}
