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

package v1

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
)

type AppSpec struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *AppSpec) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c AppSpec) ListAction() {

	ls := losapi.AppSpecList{}
	defer c.RenderJson(&ls)

	rs := data.ZoneMaster.PvScan(losapi.NsGlobalAppSpec(""), "", "", 200)
	rss := rs.KvList()
	for _, v := range rss {

		var spec losapi.AppSpec
		if err := v.Decode(&spec); err != nil {
			continue
		}

		if spec.Meta.User != c.us.UserName &&
			!spec.Roles.MatchAny(c.us.Roles) {
			continue
		}

		if c.Params.Get("qry_text") != "" &&
			!strings.Contains(spec.Meta.Name, c.Params.Get("qry_text")) {
			continue
		}

		ls.Items = append(ls.Items, spec)
	}

	ls.Kind = "AppSpecList"
}

func (c AppSpec) EntryAction() {

	set := losapi.AppSpec{}

	if c.Params.Get("fmt_json_indent") == "true" {
		defer c.RenderJsonIndent(&set, "  ")
	} else {
		defer c.RenderJson(&set)
	}

	if c.Params.Get("id") == "" {
		set.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	if obj := data.ZoneMaster.PvGet(losapi.NsGlobalAppSpec(c.Params.Get("id"))); obj.OK() {
		obj.Decode(&set)
	}

	if set.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta(losapi.ErrCodeObjectNotFound, "AppSpec Not Found")
		return
	}

	if set.Meta.User != c.us.UserName &&
		!set.Roles.MatchAny(c.us.Roles) {
		set.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if c.Params.Get("download") == "true" {
		set.Meta.ID = ""
		set.Meta.User = ""
		c.Response.Out.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=los_app_spec_%s.json", set.Meta.Name))
	}

	set.Kind = "AppSpec"
}

func (c AppSpec) SetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var req losapi.AppSpec

	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	var prev losapi.AppSpec
	if obj := data.ZoneMaster.PvGet(losapi.NsGlobalAppSpec(req.Meta.ID)); !obj.OK() {

		if !obj.NotFound() {
			set.Error = types.NewErrorMeta(losapi.ErrCodeServerError, "ServerError")
			return
		}

	} else {

		obj.Decode(&prev)

		if prev.Meta.User != c.us.UserName {
			set.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}
	}

	if prev.Meta.ID == "" {

		prev = req

		prev.Meta.ID = idhash.RandHexString(16)
		prev.Meta.Created = types.MetaTimeNow()
		prev.Meta.User = c.us.UserName

	} else {

		// TODO

		prev.Meta.Name = req.Meta.Name
		prev.Packages = req.Packages
		prev.Executors = req.Executors

		prev.ServicePorts.Clean()
		for _, v := range req.ServicePorts {

			v.Name = strings.TrimSpace(v.Name)
			if len(v.Name) == 0 {
				set.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "Invalid ServicePort Name")
				return
			}

			if v.HostPort > 0 && v.HostPort <= 1024 {
				if c.us.UserName != "sysadmin" {
					set.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied,
						"AccessDenied: Only SysAdmin can setting Host Port to 1~2014")
					return
				}
			} else {
				v.HostPort = 0
			}
			prev.ServicePorts.Sync(*v)
		}

		prev.Roles = req.Roles
	}

	prev.Meta.Updated = types.MetaTimeNow()

	// INCR Resource Version
	resVersion, _ := strconv.Atoi(prev.Meta.Version)
	resVersion++
	prev.Meta.Version = strconv.Itoa(resVersion)

	if obj := data.ZoneMaster.PvPut(losapi.NsGlobalAppSpec(prev.Meta.ID), prev, &skv.PvWriteOptions{
		Force: true,
	}); !obj.OK() {
		set.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	set.Kind = "AppSpec"
}

func (c AppSpec) CfgSetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var req losapi.AppSpec

	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if req.Configurator == nil {
		set.Error = types.NewErrorMeta("400", "No Configurator Setup")
		return
	}

	if err := req.Configurator.Name.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", "Invalid Configurator Name: "+err.Error())
		return
	}
	for _, v := range req.Configurator.Fields {

		for _, vv := range v.Validates {

			if _, err := regexp.Compile(vv.Key); err != nil {
				set.Error = types.NewErrorMeta("400", "Invalid Validator Expression: "+err.Error())
				return
			}
		}
	}

	var prev losapi.AppSpec
	if obj := data.ZoneMaster.PvGet(losapi.NsGlobalAppSpec(req.Meta.ID)); obj.OK() {
		obj.Decode(&prev)
	}

	if prev.Meta.ID == "" {
		set.Error = types.NewErrorMeta("400", "Item Not Found")
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	prev.Configurator = &losapi.AppConfigurator{
		Name: req.Configurator.Name,
	}

	for _, v := range req.Configurator.Fields {

		// TODO

		item := losapi.AppConfigField{
			Name:    v.Name,
			Title:   v.Title,
			Prompt:  v.Prompt,
			Type:    v.Type,
			Default: v.Default,
		}

		for _, ve := range v.Enums {
			item.Enums.Set(ve.Name, ve.Value)
		}

		for _, vv := range v.Validates {
			item.Validates.Set(vv.Key, vv.Value)
		}

		prev.Configurator.Fields.Sync(item)
	}

	prev.Meta.Updated = types.MetaTimeNow()

	// INCR Resource Version
	resVersion, _ := strconv.Atoi(prev.Meta.Version)
	resVersion++
	prev.Meta.Version = strconv.Itoa(resVersion)

	if obj := data.ZoneMaster.PvPut(losapi.NsGlobalAppSpec(prev.Meta.ID), prev, &skv.PvWriteOptions{
		Force: true,
	}); !obj.OK() {
		set.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	set.Kind = "AppSpec"
}
