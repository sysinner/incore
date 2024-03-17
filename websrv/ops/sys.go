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
	"fmt"
	"regexp"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"

	in_cfg "github.com/sysinner/incore/config"
	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
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

	if c.us.UserName != "sysadmin" { // TODO
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied"))
		return 1
	}

	return 0
}

func (c Sys) ConfiguratorListAction() {

	var sets inapi.SysConfiguratorList
	defer c.RenderJson(&sets)

	for _, v := range in_cfg.SysConfigurators {
		sets.Items = append(sets.Items, &inapi.SysConfigurator{
			Name:  v.Name,
			Title: v.Title,
		})
	}

	sets.Kind = "ConfiguratorList"
}

func (c Sys) ConfigWizardAction() {

	var set inapi.SysConfigWizard
	defer c.RenderJson(&set)

	name := c.Params.Value("name")
	if name == "" {
		set.Error = types.NewErrorMeta("400", "invalid name")
		return
	}

	for _, v := range in_cfg.SysConfigurators {
		if v.Name == name {
			set.Configurator = v
			break
		}
	}

	if set.Configurator == nil {
		set.Error = types.NewErrorMeta("400", "invalid name")
		return
	}

	//
	if rs := in_db.DataGlobal.NewReader(inapi.NsGlobalSysConfig(name)).Query(); rs.OK() {
		var item inapi.AppOption
		if err := rs.Decode(&item); err == nil {
			set.Option = item
		}
	}

	if set.Option.Name == "" {
		set.Option.Name = types.NameIdentifier(name)
	}

	set.Kind = "SysConfigWizard"
}

func (c Sys) ConfigSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set inapi.SysConfigGroup
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	nsName := types.NameIdentifier(set.Name)
	if err := nsName.Valid(); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request: "+err.Error())
		return
	}
	set.Name = string(nsName)

	var cfr *inapi.SysConfigurator
	for _, v := range in_cfg.SysConfigurators {
		if set.Name == v.Name {
			cfr = v
			break
		}
	}

	if cfr == nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	var prev inapi.SysConfigGroup
	if rs := in_db.DataGlobal.NewReader(inapi.NsGlobalSysConfig(set.Name)).Query(); rs.OK() {
		rs.Decode(&prev)
	}

	if prev.Name != set.Name {
		prev.Name = set.Name
	}

	for _, field := range cfr.Fields {

		var (
			value      = ""
			value_prev = ""
		)
		if v, ok := set.Items.Get(field.Name); ok {
			value = v.String()
		}
		if v, ok := prev.Items.Get(field.Name); ok {
			value_prev = v.String()
		}

		if field.AutoFill != "" {

			switch field.AutoFill {

			case inapi.AppConfigFieldAutoFillDefaultValue:
				if len(field.Default) < 1 {
					rsp.Error = types.NewErrorMeta("500", "Server Error")
					return
				}
				value = field.Default

			case inapi.AppConfigFieldAutoFillHexString_32:
				if len(value_prev) < 32 {
					value = idhash.RandHexString(32)
				} else {
					value = value_prev
				}

			case inapi.AppConfigFieldAutoFillBase64_48:
				if len(value_prev) < 44 {
					value = idhash.RandBase64String(48)
				} else {
					value = value_prev
				}

			default:
				rsp.Error = types.NewErrorMeta("500", "Server Error")
				return
			}
		}

		for _, validator := range field.Validates {

			if re, err := regexp.Compile(validator.Key); err == nil {

				if !re.MatchString(value) {
					rsp.Error = types.NewErrorMeta("400",
						fmt.Sprintf("Invalid %s/Value %s", field.Name, validator.Value))
					return
				}
			}
		}

		if len(value) > 0 {
			set.Items.Set(field.Name, value)
		}
	}

	hlog.Printf("info", "SysConfig refresh %s", set.Name)
	set.Updated = uint32(time.Now().Unix())

	if rs := in_db.DataGlobal.NewWriter(inapi.NsGlobalSysConfig(set.Name), set).Commit(); !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
		return
	}

	rsp.Kind = "SysConfig"
}
