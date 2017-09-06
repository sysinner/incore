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
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/lessos/loscore/data"
	"github.com/lessos/loscore/losapi"
)

type Resource struct {
	*httpsrv.Controller
	us iamapi.UserSession
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
		ls losapi.ResourceList
	)

	defer c.RenderJson(&ls)

	if c.Params.Get("type") != "domain" {
		ls.Error = types.NewErrorMeta("400", "Invalid Resource Type")
		return
	}

	rs := data.ZoneMaster.PvScan(losapi.NsGlobalResInstance(c.Params.Get("type")), "", "", 1000)
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rss {

		var inst losapi.Resource

		if err := v.Decode(&inst); err == nil {

			if inst.Meta.User != c.us.UserName {
				continue
			}
			if len(fields) > 0 {

				instf := losapi.Resource{
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
						bdf := &losapi.ResourceBound{}
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

/*
func (c Resource) OperatePodSetAction() {

	var set losapi.Resource
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error()}
		return
	}

	if set.Meta.Name == "" || set.Operate.AppId == "" {
		set.Error = types.NewErrorMeta("400", "Bad Request
		return
	}

	var prev losapi.Resource

	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalResInstance(set.Meta.Name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied
		return
	}

	if prev.Operate.AppId != "" ||
		prev.Operate.AppId == set.Operate.AppId {
		set.Kind = "Resource"
	} else {

		prev.Meta.Updated = types.MetaTimeNow()
		prev.Operate.AppId = set.Operate.AppId // check

		//
		data.ZoneMaster.PvPut(losapi.NsGlobalResInstance(obj_name), prev, &skv.PathWriteOptions{
			Force: true,
		})

	}

	return
}
*/
