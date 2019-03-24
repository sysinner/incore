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
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type Resource struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Resource) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c *Resource) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c Resource) ListAction() {

	var (
		ls inapi.ResourceList
	)

	defer c.RenderJson(&ls)

	if c.Params.Get("type") != "domain" {
		ls.Error = types.NewErrorMeta("400", "Invalid Resource Type")
		return
	}

	rs := data.GlobalMaster.PvScan(inapi.NsGlobalResInstance(c.Params.Get("type")), "", "", 1000)
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rss {

		var inst inapi.Resource

		if err := v.Decode(&inst); err == nil {

			// TOPO
			if c.Params.Get("filter_meta_user") == "all" &&
				iamclient.SessionAccessAllowed(c.Session, "sysinner.admin", config.Config.InstanceId) {
				//
			} else if inst.Meta.User != c.us.UserName {
				continue
			}

			if len(fields) > 0 {

				instf := inapi.Resource{
					Meta: types.InnerObjectMeta{
						ID: inst.Meta.ID,
					},
				}

				if fields.Has("meta/name") {
					instf.Meta.Name = inst.Meta.Name
				}
				if fields.Has("meta/user") {
					instf.Meta.User = inst.Meta.User
				}
				if fields.Has("meta/created") {
					instf.Meta.Created = inst.Meta.Created
				}
				if fields.Has("meta/updated") {
					instf.Meta.Updated = inst.Meta.Updated
				}

				if fields.Has("operate/app_id") {
					instf.Operate.AppId = inst.Operate.AppId
				}

				if fields.Has("action") {
					instf.Action = inst.Action
				}

				if fields.Has("description") {
					instf.Description = inst.Description
				}

				if fields.Has("bounds") {
					for _, bd := range inst.Bounds {
						bdf := &inapi.ResourceBound{}
						if fields.Has("bounds/name") {
							bdf.Name = bd.Name
						}
						instf.Bounds = append(instf.Bounds, bdf)
					}
				}

				ls.Items = append(ls.Items, instf)
			} else {
				ls.Items = append(ls.Items, inst)
			}
		}
	}

	ls.Kind = "ResourceList"
}
