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

package p1

import (
	"fmt"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type AppSpec struct {
	*httpsrv.Controller
}

var (
	public_roles = []uint32{1, 100, 101}
)

func (c AppSpec) ListAction() {

	ls := inapi.AppSpecList{}
	defer c.RenderJson(&ls)

	rs := data.GlobalMaster.PvRevScan(inapi.NsGlobalAppSpec(""), "", "", 200)
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

		if !spec.Roles.MatchAny(public_roles) {
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

			if fields.Has("depends") {
				for _, dep := range spec.Depends {
					depf := inapi.AppSpecDepend{}
					if fields.Has("depends/name") {
						depf.Name = dep.Name
					}
					specf.Depends = append(specf.Depends, depf)
				}
			}

			if fields.Has("description") {
				specf.Description = spec.Description
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
					vr.AuthUser = ""
					vr.AuthPass = ""
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

	if obj := data.GlobalMaster.PvGet(inapi.NsGlobalAppSpec(c.Params.Get("id"))); obj.OK() {
		obj.Decode(&set)
	}

	if set.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound, "AppSpec Not Found")
		return
	}

	if !set.Roles.MatchAny(public_roles) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
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
