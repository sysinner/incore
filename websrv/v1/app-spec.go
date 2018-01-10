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
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/inpack/ipapi"
	ips_data "github.com/sysinner/inpack/server/data"
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

		//
		if rs := data.ZoneMaster.ProgGet(inapi.NsGlobalAppSpecVersion(spec.Meta.ID, spec.Meta.Version)); !rs.NotFound() {
			data.ZoneMaster.ProgPut(
				inapi.NsGlobalAppSpecVersion(spec.Meta.ID, spec.Meta.Version),
				skv.NewProgValue(spec),
				nil)
		}

		if spec.Meta.User != c.us.UserName &&
			!spec.Roles.MatchAny(c.us.Roles) {
			continue
		}

		if c.Params.Get("qry_text") != "" &&
			!strings.Contains(spec.Meta.ID, c.Params.Get("qry_text")) {
			continue
		}

		if len(fields) > 0 {

			specf := inapi.AppSpec{
				Meta: types.InnerObjectMeta{
					ID:   spec.Meta.ID,
					Name: spec.Meta.Name,
				},
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

			if fields.Has("description") {
				specf.Description = spec.Description
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

func (c AppSpec) VersionListAction() {

	ls := inapi.AppSpecVersionList{}
	defer c.RenderJson(&ls)

	if c.Params.Get("id") == "" {
		ls.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	var spec inapi.AppSpec
	if rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(c.Params.Get("id"))); rs.OK() {
		rs.Decode(&spec)
	}

	if spec.Meta.User != c.us.UserName &&
		!spec.Roles.MatchAny(c.us.Roles) {
		ls.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AppSpec Not Found or Access Denied")
		return
	}

	rs := data.ZoneMaster.ProgRevScan(
		inapi.NsGlobalAppSpecVersion(spec.Meta.ID, "0"),
		inapi.NsGlobalAppSpecVersion(spec.Meta.ID, "99999999"), 50)
	rss := rs.KvList()

	for _, v := range rss {

		var spec inapi.AppSpec
		if err := v.Decode(&spec); err != nil {
			continue
		}

		ls.Items = append(ls.Items, inapi.AppSpecVersionEntry{
			Version: spec.Meta.Version,
			Created: uint64(spec.Meta.Updated),
		})
	}

	ls.Kind = "AppSpecVersionList"
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

	version := c.Params.Get("version")
	if version != "" {
		if rs := data.ZoneMaster.ProgGet(inapi.NsGlobalAppSpecVersion(c.Params.Get("id"), version)); rs.OK() {
			rs.Decode(&set)
		}
	} else if rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(c.Params.Get("id"))); rs.OK() {
		rs.Decode(&set)
	}

	if set.Meta.ID != c.Params.Get("id") {
		if version != "" {
			version = ", version " + version
		}
		set.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound,
			fmt.Sprintf("AppSpec Not Found : %s%s", c.Params.Get("id"), version))
		return
	}

	if set.Meta.User != c.us.UserName &&
		!set.Roles.MatchAny(c.us.Roles) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if version != "" && c.Params.Get("last_version") == "true" {
		if rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(set.Meta.ID)); rs.OK() {
			var last_spec inapi.AppSpec
			rs.Decode(&last_spec)
			if inapi.NewAppSpecVersion(last_spec.Meta.Version).Compare(inapi.NewAppSpecVersion(set.Meta.Version)) == 1 {
				set.LastVersion = last_spec.Meta.Version
			}
		}
	}

	if c.Params.Get("download") == "true" {
		set.Meta.User = ""
		set.Meta.Created = 0
		set.Meta.Updated = 0
		c.Response.Out.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=app_spec_%s.json", set.Meta.ID))
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

	req.Meta.ID = strings.ToLower(req.Meta.ID)
	if !inapi.AppSpecIdReg.MatchString(req.Meta.ID) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid ID")
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
		tn            = types.MetaTimeNow()
		set_new       = false
		reqVersion, _ = strconv.Atoi(req.Meta.Version)
	)

	if prev.Meta.ID == "" {

		prev = req

		prev.Meta.Created = tn
		prev.Meta.User = c.us.UserName
		set_new = true

	} else {

		prevVersion, _ := strconv.Atoi(prev.Meta.Version)
		if reqVersion == 0 {
			reqVersion = prevVersion
		} else if reqVersion < prevVersion {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid meta/version")
			return
		} else if reqVersion == prevVersion {
			reqVersion++
		}

		// TODO
		prev.Meta.Name = req.Meta.Name
		prev.Packages = req.Packages
		prev.ExpRes = req.ExpRes

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

	if reqVersion < 1 {
		reqVersion = 1
	}
	prev.Meta.Version = strconv.Itoa(reqVersion)

	//
	if prev.ExpRes.CpuMin < 100 {
		prev.ExpRes.CpuMin = 100
	}
	if fix := prev.ExpRes.CpuMin % 100; fix > 0 {
		prev.ExpRes.CpuMin += fix
	}

	//
	mem_min_min := 8 * inapi.ByteMB
	if prev.ExpRes.MemMin < mem_min_min {
		prev.ExpRes.MemMin = mem_min_min
	}
	if fix := prev.ExpRes.MemMin % mem_min_min; fix > 0 {
		prev.ExpRes.MemMin += (mem_min_min - fix)
	}

	//
	vol_min_min := 100 * inapi.ByteMB
	if prev.ExpRes.VolMin > (900 * inapi.ByteMB) {
		vol_min_min = inapi.ByteGB
	}
	if fix := prev.ExpRes.VolMin % vol_min_min; fix > 0 {
		prev.ExpRes.VolMin += (vol_min_min - fix)
	}

	for _, v := range prev.Depends {
		if rs := data.ZoneMaster.ProgGet(inapi.NsGlobalAppSpecVersion(v.Id, v.Version)); !rs.OK() {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "SpecDepend ("+v.Id+") Not Found")
			return
		}
	}

	for _, v := range prev.Packages {
		version := ipapi.PackageVersion{
			Version: types.Version(v.Version),
			Release: types.Version(v.Release),
			Dist:    v.Dist,
			Arch:    v.Arch,
		}
		if err := version.Valid(); err != nil {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, err.Error())
			return
		}
		id := ipapi.PackageMetaId(v.Name, version)
		if rs := ips_data.Data.ProgGet(ipapi.DataPackKey(id)); !rs.OK() {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "SpecPackage ("+
				ipapi.PackageFilename(v.Name, version)+") Not Found")
			return
		}
	}

	for i, v := range prev.Executors {
		if v.Priority > inapi.SpecExecutorPriorityMax {
			prev.Executors[i].Priority = inapi.SpecExecutorPriorityMax
		}
	}

	//
	if set_new {
		rs = data.ZoneMaster.PvNew(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil)
	} else {
		rs = data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil)
	}

	if !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	rs = data.ZoneMaster.ProgPut(
		inapi.NsGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version),
		skv.NewProgValue(prev),
		nil)
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
	if rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(req.Meta.ID)); rs.OK() {
		rs.Decode(&prev)
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

	if rs := data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	if rs := data.ZoneMaster.ProgPut(
		inapi.NsGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version),
		skv.NewProgValue(prev),
		nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
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
	if rs := data.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(req.Meta.ID)); rs.OK() {
		rs.Decode(&prev)
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

	if rs := data.ZoneMaster.PvPut(inapi.NsGlobalAppSpec(prev.Meta.ID), prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	if rs := data.ZoneMaster.ProgPut(
		inapi.NsGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version),
		skv.NewProgValue(prev),
		nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	set.Kind = "AppSpec"
}
