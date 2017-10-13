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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	iox_utils "github.com/lynkdb/iomix/utils"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
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

	ls := inapi.AppSpecList{}
	defer c.RenderJson(&ls)

	rs := data.ZoneMaster.PvRevScan(inapi.NsGlobalAppSpec(""), "", "", 200)
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rss {

		var spec inapi.AppSpec
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

		if len(fields) > 0 {

			specf := inapi.AppSpec{
				Meta: types.InnerObjectMeta{
					ID: spec.Meta.ID,
				},
			}

			if fields.Has("meta/name") {
				specf.Meta.Name = spec.Meta.Name
			}

			if fields.Has("meta/user") {
				specf.Meta.User = spec.Meta.User
			}

			if fields.Has("meta/version") {
				specf.Meta.Version = spec.Meta.Version
			}

			if fields.Has("meta/updated") {
				specf.Meta.Updated = spec.Meta.Updated
			}

			if fields.Has("depends") {
				for _, dep := range spec.Depends {
					depf := inapi.AppSpecDepend{}
					if fields.Has("depends/name") {
						depf.Name = dep.Name
					}
					specf.Depends = append(specf.Depends, depf)
				}
			}

			if fields.Has("packages") {
				for _, pkg := range spec.Packages {
					pkgf := inapi.VolumePackage{}
					if fields.Has("packages/name") {
						pkgf.Name = pkg.Name
					}
					specf.Packages = append(specf.Packages, pkgf)
				}
			}

			if fields.Has("executors") {
				for _, ev := range spec.Executors {
					evf := inapi.Executor{}
					if fields.Has("executors/name") {
						evf.Name = ev.Name
					}
					specf.Executors = append(specf.Executors, evf)
				}
			}

			if fields.Has("configurator") && spec.Configurator != nil {

				specf.Configurator = &inapi.AppConfigurator{}

				if fields.Has("configurator/name") {
					specf.Configurator.Name = spec.Configurator.Name
				}

				if fields.Has("configurator/fields") {
					for _, cfv := range spec.Configurator.Fields {
						cff := &inapi.AppConfigField{}
						if fields.Has("configurator/fields/name") {
							cff.Name = cfv.Name
						}
						specf.Configurator.Fields = append(specf.Configurator.Fields, cff)
					}
				}
			}

			ls.Items = append(ls.Items, specf)
		} else {
			ls.Items = append(ls.Items, spec)
		}
	}

	ls.Kind = "AppSpecList"
}

func (c AppSpec) EntryAction() {

	set := inapi.AppSpec{}

	if c.Params.Get("fmt_json_indent") == "true" {
		defer c.RenderJsonIndent(&set, "  ")
	} else {
		defer c.RenderJson(&set)
	}

	if c.Params.Get("id") == "" {
		set.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	if obj := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(c.Params.Get("id"))); obj.OK() {
		obj.Decode(&set)
	}

	if set.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound, "AppSpec Not Found")
		return
	}

	if set.Meta.User != c.us.UserName &&
		!set.Roles.MatchAny(c.us.Roles) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if c.Params.Get("download") == "true" {
		set.Meta.User = ""
		set.Meta.Created = 0
		set.Meta.Updated = 0
		c.Response.Out.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=app_spec_%s.json", set.Meta.Name))
	}

	set.Kind = "AppSpec"
}

func (c AppSpec) SetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var req inapi.AppSpec

	if err := c.Request.JsonDecode(&req); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	var prev inapi.AppSpec
	rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(req.Meta.ID))
	if !rs.OK() {
		if !rs.NotFound() {
			set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "ServerError")
			return
		}
	} else {
		rs.Decode(&prev)
		if prev.Meta.User != c.us.UserName {
			set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}
	}

	var (
		tn      = types.MetaTimeNow()
		set_new = false
	)

	if prev.Meta.ID == "" {

		prev = req

		prev.Meta.ID = iox_utils.Uint32ToHexString(uint32(tn.Time().Unix())) + idhash.RandHexString(8)
		prev.Meta.Created = tn
		prev.Meta.User = c.us.UserName
		set_new = true

	} else {

		// TODO

		prev.Meta.Name = req.Meta.Name
		prev.Packages = req.Packages

		prev.Depends = []inapi.AppSpecDepend{}
		for _, v := range req.Depends {
			if err := v.Valid(); err != nil {
				set.Error = types.NewErrorMeta("400", "Bad Request")
				return
			}
			if v.Id == prev.Meta.ID {
				continue
			}
			if types.IterObjectGet(prev.Depends, v.Id) == nil {
				prev.Depends = append(prev.Depends, v)
			}
		}

		prev.Executors = req.Executors

		prev.ServicePorts.Clean()
		for _, v := range req.ServicePorts {

			v.Name = strings.TrimSpace(v.Name)
			if len(v.Name) == 0 {
				set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "Invalid ServicePort Name")
				return
			}

			if v.HostPort > 0 && v.HostPort <= 1024 {
				if c.us.UserName != "sysadmin" {
					set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied,
						"AccessDenied: Only SysAdmin can setting Host Port to 1~2014")
					return
				}
			} else {
				v.HostPort = 0
			}
			prev.ServicePorts.Sync(*v)
		}

		if req.Configurator != nil {

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
			prev.Configurator = req.Configurator
		}

		prev.Roles = req.Roles
	}

	prev.Meta.Updated = tn

	// INCR Resource Version
	resVersion, _ := strconv.Atoi(prev.Meta.Version)
	resVersion++
	prev.Meta.Version = strconv.Itoa(resVersion)

	if set_new {
		rs = data.ZoneMaster.PvNew(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil)
	} else {
		rs = data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil)
	}

	if !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
	} else {
		set.Kind = "AppSpec"
	}
}

func (c AppSpec) CfgSetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var req inapi.AppSpec

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

	var prev inapi.AppSpec
	if obj := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(req.Meta.ID)); obj.OK() {
		obj.Decode(&prev)
	}

	if prev.Meta.ID == "" {
		set.Error = types.NewErrorMeta("400", "Item Not Found")
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	prev.Configurator = &inapi.AppConfigurator{
		Name: req.Configurator.Name,
	}

	for _, v := range req.Configurator.Fields {

		// TODO

		item := inapi.AppConfigField{
			Name:     v.Name,
			Title:    v.Title,
			Prompt:   v.Prompt,
			Type:     v.Type,
			Default:  v.Default,
			AutoFill: v.AutoFill,
		}

		if item.AutoFill != "" && !inapi.AppConfigFieldAutoFillValid(item.AutoFill) {
			set.Error = types.NewErrorMeta("400", "Invalid AutoFill Value")
			return
		}

		if item.AutoFill == "" {

			for _, ve := range v.Enums {
				item.Enums.Set(ve.Name, ve.Value)
			}

			for _, vv := range v.Validates {
				item.Validates.Set(vv.Key, vv.Value)
			}
		}

		prev.Configurator.Fields.Sync(item)
	}

	prev.Meta.Updated = types.MetaTimeNow()

	// INCR Resource Version
	resVersion, _ := strconv.Atoi(prev.Meta.Version)
	resVersion++
	prev.Meta.Version = strconv.Itoa(resVersion)

	if obj := data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil); !obj.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	set.Kind = "AppSpec"
}

func (c AppSpec) CfgFieldDelAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var req inapi.AppSpec

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

	var prev inapi.AppSpec
	if obj := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(req.Meta.ID)); obj.OK() {
		obj.Decode(&prev)
	}

	if prev.Meta.ID == "" {
		set.Error = types.NewErrorMeta("400", "Item Not Found")
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	for _, v := range req.Configurator.Fields {

		for _, vdel := range prev.Configurator.Fields {

			if v.Name == vdel.Name {
				prev.Configurator.Fields.Del(v.Name)
				break
			}
		}
	}

	prev.Meta.Updated = types.MetaTimeNow()

	// INCR Resource Version
	resVersion, _ := strconv.Atoi(prev.Meta.Version)
	resVersion++
	prev.Meta.Version = strconv.Itoa(resVersion)

	if obj := data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil); !obj.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	set.Kind = "AppSpec"
}
