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
	"time"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	in_cfg "github.com/sysinner/incore/config"
	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	inStatus "github.com/sysinner/incore/status"
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
	ZoneId           string                  `json:"zone_id"`
	ZoneMaster       in_cfg.ZoneMaster       `json:"zone_master"`
	SysConfigs       []*inapi.SysConfigGroup `json:"sys_configs,omitempty"`
	sysConfigUpdated int64                   `json:"-"`
}

var (
	sysCfg *SysCfg
)

func (c *Sys) CfgAction() {

	tn := time.Now().Unix()

	if sysCfg == nil {

		sysCfg = &SysCfg{
			ZoneId: in_cfg.Config.Host.ZoneId,
		}
		sysCfg.ZoneMaster = in_cfg.Config.ZoneMaster
	}

	if (sysCfg.sysConfigUpdated + 60) < tn {

		sysCfg.SysConfigs = []*inapi.SysConfigGroup{}

		for _, v := range in_cfg.SysConfigurators {

			if !v.ReadRoles.MatchAny(c.us.Roles) {
				continue
			}

			//
			if rs := in_db.GlobalMaster.KvGet(inapi.NsGlobalSysConfig(v.Name)); rs.OK() {
				var item inapi.SysConfigGroup
				if err := rs.Decode(&item); err == nil {
					sysCfg.SysConfigs = append(sysCfg.SysConfigs, &item)
					inStatus.ZoneSysConfigGroupList.Sync(&item)
				}
			}
		}

		sysCfg.sysConfigUpdated = tn
	}

	c.RenderJson(&sysCfg)
}
