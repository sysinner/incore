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
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/htoml4g/htoml"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"

	"github.com/sysinner/inpack/ipapi"
)

type AppSpec struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

var (
	appSpecVersionCaches sync.Map
)

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

func (c *AppSpec) accessAllow(privilege string) bool {
	if iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.Zone.InstanceId) {
		return true
	}
	return false
}

func (c AppSpec) TypeTagListAction() {
	c.RenderJson(inapi.WebServiceReply{
		Kind:  "AppSpecTypeTagList",
		Items: inapi.AppSpecTypeTagDicts,
	})
}

func (c AppSpec) ListAction() {

	ls := inapi.AppSpecList{}
	defer c.RenderJson(&ls)

	rs := data.DataGlobal.NewRanger(
		inapi.NsGlobalAppSpec("zzzzzzzz"), inapi.NsGlobalAppSpec("")).
		SetRevert(true).
		SetLimit(200).Exec()

	var fields types.ArrayPathTree
	if fns := c.Params.Value("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rs.Items {

		var spec inapi.AppSpec
		if err := v.JsonDecode(&spec); err != nil {
			continue
		}

		//
		if _, ok := appSpecVersionCaches.Load(spec.Meta.ID + ":" + spec.Meta.Version); !ok {
			if rs := data.DataGlobal.NewReader(
				inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, spec.Meta.Version)).Exec(); !rs.NotFound() {
				data.DataGlobal.NewWriter(inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, spec.Meta.Version), spec).Exec()
			}
			appSpecVersionCaches.Store(spec.Meta.ID+":"+spec.Meta.Version, true)
		}

		if spec.Meta.User != c.us.UserName &&
			!spec.Roles.MatchAny(c.us.Roles) {
			continue
		}

		if c.Params.Value("qry_text") != "" &&
			!strings.Contains(spec.Meta.ID, c.Params.Value("qry_text")) {
			continue
		}

		if len(fields) > 0 {

			specf := inapi.AppSpec{
				Meta: types.InnerObjectMeta{
					ID:   spec.Meta.ID,
					Name: spec.Meta.Name,
				},
			}

			if fields.Has("meta/subtitle") {
				specf.Meta.Subtitle = spec.Meta.Subtitle
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

			if fields.Has("comment") {
				specf.Comment = spec.Comment
			}

			if fields.Has("type_tags") {
				specf.TypeTags = spec.TypeTags
			}

			if fields.Has("urls") {
				specf.Urls = spec.Urls
			}

			if fields.Has("depends") {
				for _, dep := range spec.Depends {
					depf := &inapi.AppSpecDepend{}
					if fields.Has("depends/name") {
						depf.Name = dep.Name
					}
					specf.Depends = append(specf.Depends, depf)
				}
			}

			if fields.Has("dep_remotes") {
				for _, dep := range spec.DepRemotes {
					depf := &inapi.AppSpecDepend{}
					if fields.Has("dep_remote/name") {
						depf.Name = dep.Name
					}
					specf.DepRemotes = append(specf.DepRemotes, depf)
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

			if fields.Has("vcs_repos") {
				for _, vr := range spec.VcsRepos {
					if vr.AuthPass != "" {
						vr.AuthPass = "********"
					}
					specf.VcsRepos = append(specf.VcsRepos, vr)
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

			ls.Items = append(ls.Items, &specf)
		} else {
			ls.Items = append(ls.Items, &spec)
		}
	}

	sort.Slice(ls.Items, func(i, j int) bool {
		return ls.Items[i].Meta.Updated > ls.Items[j].Meta.Updated
	})

	ls.Kind = "AppSpecList"
}

func (c AppSpec) VersionListAction() {

	ls := inapi.AppSpecVersionList{}
	defer c.RenderJson(&ls)

	if c.Params.Value("id") == "" {
		ls.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	var (
		version = c.Params.Value("version")
	)

	var spec inapi.AppSpec
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(c.Params.Value("id"))).Exec(); rs.OK() {
		rs.Item().JsonDecode(&spec)
	}

	if spec.Meta.User != c.us.UserName &&
		!spec.Roles.MatchAny(c.us.Roles) {
		ls.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AppSpec Not Found or Access Denied")
		return
	}

	// TODO
	rs := data.DataGlobal.NewRanger(
		inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, "99999999.0.0"),
		inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, "0")).
		SetRevert(true).SetLimit(1000).Exec()
	var (
		prevVersion = ""
		lastCount   = 0
	)

	for _, v := range rs.Items {

		var spec inapi.AppSpec
		if err := v.JsonDecode(&spec); err != nil {
			continue
		}

		if cp := inapi.NewAppSpecVersion(spec.Meta.Version).Compare(
			inapi.NewAppSpecVersion(version)); cp < 0 {

			if prevVersion == "" {
				prevVersion = spec.Meta.Version
			} else {
				break
			}

		} else if cp > 0 {

			if lastCount >= 10 {
				continue
			}
			lastCount += 1
		}

		ls.Items = append(ls.Items, inapi.AppSpecVersionEntry{
			Version: spec.Meta.Version,
			Created: uint64(spec.Meta.Updated),
			Comment: spec.Comment,
		})
	}

	ls.Kind = "AppSpecVersionList"
}

func (c AppSpec) ItemDelAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	if c.Params.Value("id") == "" {
		set.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	var spec inapi.AppSpec
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(c.Params.Value("id"))).Exec(); rs.OK() {
		rs.Item().JsonDecode(&spec)
	}

	if spec.Meta.ID != c.Params.Value("id") {
		set.Error = types.NewErrorMeta("400", "Item Not Found")
		return
	}

	if spec.Meta.User != c.us.UserName &&
		!spec.Roles.MatchAny(c.us.Roles) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if rs := data.DataGlobal.NewRanger(
		inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, ""),
		inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, "99999999.0.0")).
		SetLimit(10000).Exec(); rs.OK() {
		for _, v := range rs.Items {
			var item inapi.AppSpec
			if err := v.JsonDecode(&item); err == nil {
				if rs := data.DataGlobal.NewDeleter(
					inapi.NsKvGlobalAppSpecVersion(spec.Meta.ID, item.Meta.Version)).Exec(); !rs.OK() {
					set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "Server Error "+rs.ErrorMessage())
					return
				}
			}
		}

	} else if !rs.NotFound() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "Server Error")
		return
	}

	if rs := data.DataGlobal.NewDeleter(inapi.NsGlobalAppSpec(spec.Meta.ID)).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "Server Error "+rs.ErrorMessage())
		return
	}

	hlog.Printf("info", "AppSpec %s, remove", spec.Meta.ID)

	set.Kind = "AppSpec"
}

func (c AppSpec) EntryAction() {

	var (
		rsp inapi.AppSpec
		set inapi.AppSpec
	)

	if c.Params.Value("ct") == "toml" {
		defer func() {
			bs, _ := htoml.Encode(&rsp, nil)
			c.Response.Out.Header().Set("Content-Type", "application/toml")
			c.RenderString(string(bs))
		}()
	} else if c.Params.Value("fmt_json_indent") == "true" {
		defer c.RenderJsonIndent(&rsp, "  ")
	} else {
		defer c.RenderJson(&rsp)
	}

	if c.Params.Value("id") == "" {
		rsp.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	version := c.Params.Value("version")
	if version != "" {
		if rs := data.DataGlobal.NewReader(
			inapi.NsKvGlobalAppSpecVersion(c.Params.Value("id"), version)).Exec(); rs.OK() {
			rs.Item().JsonDecode(&set)
		}
	}

	if set.Meta.ID != c.Params.Value("id") {
		if rs := data.DataGlobal.NewReader(
			inapi.NsGlobalAppSpec(c.Params.Value("id"))).Exec(); rs.OK() {
			rs.Item().JsonDecode(&set)
		}
	}

	if set.Meta.ID != c.Params.Value("id") {

		appId := c.Params.Value("app_id")

		if inapi.AppIdRe2.MatchString(appId) {

			if rs := data.DataGlobal.NewReader(
				inapi.NsGlobalAppInstance(appId)).Exec(); rs.OK() {
				var app inapi.AppInstance
				rs.Item().JsonDecode(&app)
				if app.Meta.ID == appId && app.Spec.Meta.ID == c.Params.Value("id") {
					set = app.Spec
				}
			}
		}
	}

	if set.Meta.ID != c.Params.Value("id") {

		if version != "" {
			version = ", version " + version
		}

		rsp.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound,
			fmt.Sprintf("AppSpec Not Found : %s%s", c.Params.Value("id"), version))

		return
	}

	if set.Meta.User != c.us.UserName &&
		!set.Roles.MatchAny(c.us.Roles) {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if version != "" && c.Params.Value("last_version") == "true" {
		if rs := data.DataGlobal.NewReader(
			inapi.NsGlobalAppSpec(set.Meta.ID)).Exec(); rs.OK() {
			var last_spec inapi.AppSpec
			rs.Item().JsonDecode(&last_spec)
			if inapi.NewAppSpecVersion(last_spec.Meta.Version).Compare(inapi.NewAppSpecVersion(set.Meta.Version)) == 1 {
				set.LastVersion = last_spec.Meta.Version
			}
		}
	}

	if c.Params.Value("download") == "true" {
		set.Meta.User = ""
		set.Meta.Created = 0
		set.Meta.Updated = 0
		fileExt := "json"
		if c.Params.Value("ct") == "toml" {
			fileExt = "toml"
		}
		c.Response.Out.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=app_spec_%s.%s", set.Meta.ID, fileExt))
	}

	rsp = set

	if rsp.Configurator != nil {
		for _, ft := range rsp.Configurator.Fields {
			if ft.Type == 3 {
				ft.Type = 300
			}
		}
	}

	rsp.Kind = "AppSpec"
}

func (c AppSpec) SetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	//
	var (
		req inapi.AppSpec
		err error
	)

	if len(c.Request.RawBody()) < 10 {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if c.Request.RawBody()[0] != '{' {
		err = htoml.Decode(c.Request.RawBody(), &req)
	} else {
		err = c.Request.JsonDecode(&req)
	}

	if err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	req.Meta.ID = strings.ToLower(req.Meta.ID)
	if !inapi.AppSpecIdReg.MatchString(req.Meta.ID) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid ID")
		return
	}

	var prev inapi.AppSpec
	rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(req.Meta.ID)).Exec()
	if !rs.OK() {
		if !rs.NotFound() {
			set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, "ServerError")
			return
		}
	} else {
		rs.Item().JsonDecode(&prev)
		if prev.Meta.User != c.us.UserName {
			set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}
	}

	var (
		tn         = types.MetaTimeNow()
		setNew     = false
		reqVersion = inapi.NewAppSpecVersion(req.Meta.Version)
	)

	if err = inapi.ValidUtf8String(req.Meta.Name, 1, 30); err != nil {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Title "+err.Error())
		return
	}

	if err = inapi.ValidUtf8String(req.Meta.Subtitle, 0, 100); err != nil {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Subtitle "+err.Error())
		return
	}

	if err = inapi.ValidUtf8String(req.Description, 0, 2000); err != nil {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Description "+err.Error())
		return
	}

	if len(req.Urls) > 0 {
		urls := []*inapi.AppSpecUrlEntry{}
		for _, v := range req.Urls {
			v.Name = strings.ToLower(v.Name)
			if !inapi.AppSpecUrlNameRE.MatchString(v.Name) {
				set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "invalid urls[]/name "+v.Name)
				return
			}
			if u, e := url.Parse(v.Url); e != nil {
				set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "invalid urls[]/url "+v.Url)
				return
			} else {
				v.Url = u.String()
			}
			if rs, _ := inapi.SliceMerge(urls, v, func(i int) bool {
				return urls[i].Name == v.Name
			}); rs != nil {
				urls = rs.([]*inapi.AppSpecUrlEntry)
			}
		}
	}

	if req.ExpRes == nil {
		req.ExpRes = &inapi.AppSpecResRequirements{}
	}

	if req.ExpDeploy == nil {
		req.ExpDeploy = &inapi.AppSpecExpDeployRequirements{}
	}

	if prev.Meta.ID == "" {

		prev = req

		prev.Meta.Created = tn
		prev.Meta.User = c.us.UserName
		setNew = true

	} else {

		prevVersion := inapi.NewAppSpecVersion(prev.Meta.Version)

		if reqVersion.IndexId() == 0 {
			reqVersion = prevVersion
			reqVersion.Add(false, false, true)
		} else {

			cn := reqVersion.Compare(prevVersion)
			if cn == 0 ||
				(reqVersion.Major == prevVersion.Major &&
					reqVersion.Minor == prevVersion.Minor) {
				reqVersion = prevVersion
				reqVersion.Add(false, false, true)
			} else if cn == -1 {
				set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid meta/version")
				return
			}
		}

		// TODO
		prev.Meta.Name = req.Meta.Name
		prev.Meta.Subtitle = req.Meta.Subtitle
		prev.Packages = req.Packages
		prev.VcsRepos = req.VcsRepos
		prev.ExpRes = req.ExpRes
		prev.ExpDeploy = req.ExpDeploy

		prev.Description = req.Description
		prev.TypeTags = req.TypeTags
		prev.Comment = req.Comment
		prev.Urls = req.Urls

		prev.Depends = []*inapi.AppSpecDepend{}
		for _, v := range req.Depends {
			if err := v.Valid(); err != nil {
				set.Error = types.NewErrorMeta("400", "Bad Request")
				return
			}
			if v.Id == prev.Meta.ID {
				continue
			}
			if inapi.AppSpecDependSliceGet(prev.Depends, v.Id) == nil {
				prev.Depends = append(prev.Depends, v)
			}
		}

		prev.DepRemotes = []*inapi.AppSpecDepend{}
		for _, v := range req.DepRemotes {
			if err := v.Valid(); err != nil {
				set.Error = types.NewErrorMeta("400", "Bad Request")
				return
			}
			if v.Id == prev.Meta.ID {
				continue
			}
			if inapi.AppSpecDependSliceGet(prev.DepRemotes, v.Id) == nil {
				prev.DepRemotes = append(prev.DepRemotes, v)
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

			if v.HostPort > 9999 {
				set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid HostPort")
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

		if len(req.RuntimeImages) > 0 {
			prev.RuntimeImages = req.RuntimeImages
		}
	}

	images := types.ArrayString{}
	for _, v := range prev.RuntimeImages {

		if v = strings.Trim(strings.TrimSpace(strings.ToLower(v)), "/"); v == "" {
			continue
		}

		if !inapi.OCINameRE.MatchString(v) {
			set.Error = types.NewErrorMeta("400", "Invalid Runtime Image Name : "+v)
			return
		}

		if !strings.HasPrefix(v, "sysinner/") &&
			!c.accessAllow("sysinner.admin") {
			set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied,
				"Access Denied : Only administrators can setup third-party images")
			return
		}
		images.Set(v)
	}
	if len(images) > 0 {
		prev.RuntimeImages = []string(images)
	} else {
		prev.RuntimeImages = nil
	}

	prev.Fix()

	prev.Meta.Updated = tn

	prev.Meta.Version = reqVersion.FullVersion()

	//
	if prev.ExpRes.CpuMin < 1 {
		prev.ExpRes.CpuMin = 1
	}

	//
	memMinMin := int32(32) // in MB
	if prev.ExpRes.MemMin < memMinMin {
		prev.ExpRes.MemMin = memMinMin
	}
	if fix := prev.ExpRes.MemMin % memMinMin; fix > 0 {
		prev.ExpRes.MemMin += (memMinMin - fix)
	}

	//
	if prev.ExpDeploy.RepMin < inapi.AppSpecExpDeployRepNumMin {
		prev.ExpDeploy.RepMin = inapi.AppSpecExpDeployRepNumMin
	}
	if prev.ExpDeploy.RepMax > inapi.AppSpecExpDeployRepNumMax {
		prev.ExpDeploy.RepMax = inapi.AppSpecExpDeployRepNumMax
	}
	if prev.ExpDeploy.RepMin > prev.ExpDeploy.RepMax {
		prev.ExpDeploy.RepMin = prev.ExpDeploy.RepMax
	}

	//
	if prev.ExpDeploy.SysState != inapi.AppSpecExpDeploySysStateless {
		prev.ExpDeploy.SysState = inapi.AppSpecExpDeploySysStateful
	}

	//
	if prev.ExpDeploy.NetworkMode == inapi.AppSpecExpDeployNetworkModeHost {

		if c.us.UserName != "sysadmin" {
			set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied,
				"AccessDenied: Only SysAdmin can setting network mode to HOST")
			return
		}
	} else {
		prev.ExpDeploy.NetworkMode = inapi.AppSpecExpDeployNetworkModeBridge
	}

	//
	if prev.ExpDeploy.NetworkVpcName != inapi.AppSpecExpDeployNetworkVpcNameV1 {
		prev.ExpDeploy.NetworkVpcName = ""
	}

	//
	if prev.ExpDeploy.FailoverTime < 300 {
		prev.ExpDeploy.FailoverTime = 300
	}
	if prev.ExpDeploy.FailoverNumMax < 0 {
		prev.ExpDeploy.FailoverNumMax = 0
	} else if prev.ExpDeploy.FailoverNumMax > prev.ExpDeploy.RepMax {
		prev.ExpDeploy.FailoverNumMax = prev.ExpDeploy.RepMax
	}
	if prev.ExpDeploy.FailoverRateMax < 0 {
		prev.ExpDeploy.FailoverRateMax = 0
	} else if prev.ExpDeploy.FailoverRateMax > 100 {
		prev.ExpDeploy.FailoverRateMax = 100
	}

	// in GB
	if prev.ExpRes.VolMin < 1 {
		prev.ExpRes.VolMin = 1
	} else if prev.ExpRes.VolMin > 200 {
		prev.ExpRes.VolMin = 200
	}

	appSpecSets := types.ArrayString([]string{prev.Meta.ID})

	for _, v := range prev.Depends {

		if appSpecSets.Has(v.Id) {
			set.Error = types.NewErrorMeta(inapi.ErrCodeObjectPathConflict,
				"Internally dependent AppSpec ("+v.Id+") Conflict with others")
			return
		}
		appSpecSets.Set(v.Id)

		var (
			vs = inapi.NewAppSpecVersion(v.Version)
		)
		v.Version = vs.PrefixString()
		vs.Patch = 99999999

		if rs := data.DataGlobal.NewRanger(
			inapi.NsKvGlobalAppSpecVersion(v.Id, vs.MajorMinorVersion()),
			inapi.NsKvGlobalAppSpecVersion(v.Id, vs.FullVersion())).
			SetLimit(1).Exec(); !rs.OK() || len(rs.Items) == 0 {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
				"Internally dependent AppSpec ("+v.Id+") Not Found")
			return
		}
	}

	for _, v := range prev.DepRemotes {

		if appSpecSets.Has(v.Id) {
			set.Error = types.NewErrorMeta(inapi.ErrCodeObjectPathConflict,
				"Remotely dependent AppSpec ("+v.Id+") Conflict with others")
			return
		}
		appSpecSets.Set(v.Id)

		var (
			vs = inapi.NewAppSpecVersion(v.Version)
		)
		v.Version = vs.PrefixString()
		vs.Patch = 99999999

		if rs := data.DataGlobal.NewRanger(
			inapi.NsKvGlobalAppSpecVersion(v.Id, vs.MajorMinorVersion()),
			inapi.NsKvGlobalAppSpecVersion(v.Id, vs.FullVersion())).
			SetLimit(1).Exec(); !rs.OK() || len(rs.Items) == 0 {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
				"Remotely dependent AppSpec ("+v.Id+") Not Found")
			return
		}
	}

	for _, v := range prev.Packages {

		version := ipapi.PackVersion{
			Version: types.Version(v.Version),
		}

		if !version.Version.Valid() {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
				fmt.Sprintf("invalid version %s", v.Version))
			return
		}

		// if rs := data.DataInpack.NewRanger(
		// 	ipapi.DataPackKey(fmt.Sprintf("%s-%s", v.Name, v.Version)),
		// 	ipapi.DataPackKey(fmt.Sprintf("%s-%sz", v.Name, v.Version)),
		// ).SetLimit(1).Exec(); !rs.OK() {

		// 	set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
		// 		fmt.Sprintf("Package %s/%s Not Found", v.Name, v.Version))
		// 	return
		// }

		if rs := data.DataPack.NewRanger(
			ipapi.DataPackKey(fmt.Sprintf("%s-%s", v.Name, v.Version)),
			ipapi.DataPackKey(fmt.Sprintf("%s-%sz", v.Name, v.Version)),
		).SetLimit(1).Exec(); !rs.OK() {

			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
				fmt.Sprintf("Package %s/%s Not Found", v.Name, v.Version))
			return
		}
	}

	if len(prev.VcsRepos) > 0 {
		var vcsRepos inapi.VcsRepoItems
		for _, v := range prev.VcsRepos {
			if err := v.Valid(); err != nil {
				set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, err.Error())
				return
			}
			vcsRepos.Set(v)
		}
		prev.VcsRepos = vcsRepos
	}

	for i, v := range prev.Executors {
		if v.Priority > inapi.SpecExecutorPriorityMax {
			prev.Executors[i].Priority = inapi.SpecExecutorPriorityMax
		}
	}

	prev.Reset()

	//
	if setNew {
		rs = data.DataGlobal.NewWriter(inapi.NsGlobalAppSpec(prev.Meta.ID), prev).
			SetCreateOnly(true).Exec()
	} else {
		rs = data.DataGlobal.NewWriter(inapi.NsGlobalAppSpec(prev.Meta.ID), prev).Exec()
	}

	if !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
		return
	}

	rs = data.DataGlobal.NewWriter(
		inapi.NsKvGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version), prev).Exec()
	if !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
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

	if err := req.Configurator.Valid(); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(req.Meta.ID)).Exec(); rs.OK() {
		rs.Item().JsonDecode(&prev)
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

		v.Default = strings.TrimSpace(v.Default)

		item := inapi.AppConfigField{
			Name:        v.Name,
			Title:       v.Title,
			Description: v.Description,
			Prompt:      v.Prompt,
			Type:        v.Type,
			Default:     v.Default,
			AutoFill:    v.AutoFill,
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

	resVersion := inapi.NewAppSpecVersion(prev.Meta.Version)
	resVersion.Add(false, false, true)
	prev.Meta.Version = resVersion.FullVersion()

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppSpec(prev.Meta.ID), prev).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
		return
	}

	if rs := data.DataGlobal.NewWriter(
		inapi.NsKvGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version), prev).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(req.Meta.ID)).Exec(); rs.OK() {
		rs.Item().JsonDecode(&prev)
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

	resVersion := inapi.NewAppSpecVersion(prev.Meta.Version)
	resVersion.Add(false, false, true)
	prev.Meta.Version = resVersion.FullVersion()

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppSpec(prev.Meta.ID), prev).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
		return
	}

	if rs := data.DataGlobal.NewWriter(
		inapi.NsKvGlobalAppSpecVersion(prev.Meta.ID, prev.Meta.Version), prev).Exec(); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.ErrorMessage())
		return
	}

	set.Kind = "AppSpec"
}

func appSpecVersionLastPatch(specId, version string) *inapi.AppSpec {

	var (
		spec inapi.AppSpec
		v    = inapi.NewAppSpecVersion(version)
	)

	v.Patch = 99999999

	if rs := data.DataGlobal.NewRanger(
		inapi.NsKvGlobalAppSpecVersion(specId, v.FullVersion()),
		inapi.NsKvGlobalAppSpecVersion(specId, v.MajorMinorVersion())).
		SetRevert(true).Exec(); rs.OK() && len(rs.Items) > 0 {
		rs.Items[0].JsonDecode(&spec)
		if spec.Meta.ID == specId {
			return &spec
		}
	}

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppSpec(specId)).
		Exec(); rs.OK() {
		rs.Item().JsonDecode(&spec)
		if spec.Meta.ID == specId {
			return &spec
		}
	}

	return nil
}
