// Copyright 2018 Eryx <evorui аt gmail dοt com>, All rights reserved.
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
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	in_cfg "github.com/sysinner/incore/config"
)

type Sys struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Sys) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

type SysCfg struct {
	ZoneId     string            `json:"zone_id"`
	ZoneMaster in_cfg.ZoneMaster `json:"zone_master"`
}

var (
	sysCfg *SysCfg
)

func (c *Sys) CfgAction() {
	if sysCfg == nil {
		sysCfg = &SysCfg{
			ZoneId: in_cfg.Config.Host.ZoneId,
		}
		sysCfg.ZoneMaster = in_cfg.Config.ZoneMaster
	}
	c.RenderJson(&sysCfg)
}
