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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

var (
	publicRoles    = []uint32{1, 100, 101}
	appSpecMu      sync.RWMutex
	appSpecItems   []*inapi.AppSpec
	appSpecUpdated int64
)

type AppSpec struct {
	*httpsrv.Controller
}

func (c AppSpec) TypeTagListAction() {
	c.RenderJson(inapi.WebServiceReply{
		Kind:  "AppSpecTypeTagList",
		Items: inapi.AppSpecTypeTagDicts,
	})
}

func appSpecRefresh() {

	tn := time.Now().Unix()

	if (appSpecUpdated + 60) > tn {
		return
	}

	appSpecMu.Lock()
	defer appSpecMu.Unlock()

	var (
		rs = data.DataGlobal.NewReader(nil).
			KeyRangeSet(inapi.NsGlobalAppSpec(""), inapi.NsGlobalAppSpec("zzzz")).
			LimitNumSet(1000).Query()
		items = []*inapi.AppSpec{}
	)

	for _, v := range rs.Items {

		var item inapi.AppSpec
		if err := v.Decode(&item); err != nil {
			continue
		}

		items = append(items, &item)
	}

	appSpecUpdated = tn

	if len(items) > 0 {

		sort.Slice(items, func(i, j int) bool {
			return items[i].Meta.Updated > items[j].Meta.Updated
		})

		appSpecItems = items

	} else {
		appSpecUpdated -= 50
	}
}

func (c AppSpec) ListAction() {

	ls := inapi.AppSpecList{}
	defer c.RenderJson(&ls)

	appSpecRefresh()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	tags := []string{}
	if v := c.Params.Get("type_tags"); v != "" {
		tags = strings.Split(v, ",")
	}

	for _, spec := range appSpecItems {

		if !spec.Roles.MatchAny(publicRoles) {
			continue
		}

		if c.Params.Get("qry_text") != "" &&
			!strings.Contains(spec.Meta.ID, c.Params.Get("qry_text")) {
			continue
		}

		if len(tags) > 0 {
			thit := false
			for _, t := range tags {
				for _, t0 := range spec.TypeTags {
					if t == t0 {
						thit = true
						break
					}
				}
			}
			if !thit {
				continue
			}
		}

		if len(fields) > 0 {

			specf := &inapi.AppSpec{
				Meta: types.InnerObjectMeta{
					ID:   spec.Meta.ID,
					Name: spec.Meta.Name,
				},
			}

			if fields.Has("meta/user") {
				specf.Meta.User = spec.Meta.User
			}

			if fields.Has("meta/subtitle") {
				specf.Meta.Subtitle = spec.Meta.Subtitle
			}

			if fields.Has("meta/version") {
				specf.Meta.Version = spec.Meta.Version
			}

			if fields.Has("meta/updated") {
				specf.Meta.Updated = spec.Meta.Updated
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

			if fields.Has("description") {
				specf.Description = spec.Description
			}

			if fields.Has("type_tags") {
				specf.TypeTags = spec.TypeTags
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

	if c.Params.Get("type_tag_dicts") == "yes" {
		ls.TypeTagDicts = inapi.AppSpecTypeTagDicts
	}
}

func (c AppSpec) EntryAction() {

	set := inapi.AppSpec{}

	if c.Params.Get("fmt_json_indent") == "true" {
		defer c.RenderJsonIndent(&set, "  ")
	} else {
		defer c.RenderJson(&set)
	}

	appSpecRefresh()

	if c.Params.Get("id") == "" {
		set.Error = types.NewErrorMeta("400", "ID can not be null")
		return
	}

	for _, v := range appSpecItems {
		if v.Meta.ID == c.Params.Get("id") {
			set = *v
			break
		}
	}

	if set.Meta.ID != c.Params.Get("id") {
		set.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound, "AppSpec Not Found")
		return
	}

	if !set.Roles.MatchAny(publicRoles) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if c.Params.Get("download") == "true" {
		set.Meta.User = ""
		set.Meta.Created = 0
		set.Meta.Updated = 0
		set.LastVersion = ""
		c.Response.Out.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=app_spec_%s.json", set.Meta.ID))
	}

	set.Kind = "AppSpec"
}
