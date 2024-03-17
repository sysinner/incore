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

package cp

import (
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamclient"
	"github.com/sysinner/incore/config"
)

func NewModule() *httpsrv.Module {

	mod := httpsrv.NewModule()

	mod.RegisterFileServer("/~", config.Prefix+"/webui/in", nil)

	mod.RegisterFileServer("/-", config.Prefix+"/webui/in/cp/tpl", nil)

	mod.RegisterController(new(Index), new(iamclient.Auth))

	return mod
}

func NewIndexModule() *httpsrv.Module {

	mod := httpsrv.NewModule()

	mod.RegisterFileServer("/~", config.Prefix+"/webui", nil)

	mod.RegisterController(new(Index), new(iamclient.Auth))

	return mod
}
