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
	"strings"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lessos/iam/iamclient"
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/httpsrv"
	"github.com/lessos/lessgo/logger"
	"github.com/lessos/lessgo/types"

	los_db "code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
)

type AppInst struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *AppInst) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c AppInst) ListAction() {

	ls := losapi.AppInstanceList{}
	defer c.RenderJson(&ls)

	// TODO pager
	rs := los_db.ZoneMaster.PvScan(losapi.NsGlobalAppInstance(""), "", "", 1000)
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rss {

		var inst losapi.AppInstance

		if err := v.Decode(&inst); err != nil {
			continue
		}

		if inst.Meta.User != c.us.UserName {
			continue
		}

		if c.Params.Get("operate_option") != "" {

			if opt := inst.Operate.Options.Get(c.Params.Get("operate_option")); opt == nil || opt.Ref != nil {
				continue
			}
		}

		if c.Params.Get("qry_text") != "" &&
			!strings.Contains(inst.Meta.Name, c.Params.Get("qry_text")) {
			continue
		}

		if len(fields) > 0 {

			instf := losapi.AppInstance{
				Meta: types.InnerObjectMeta{
					ID: inst.Meta.ID,
				},
			}

			if fields.Has("meta/name") {
				instf.Meta.Name = inst.Meta.Name
			}

			if fields.Has("meta/updated") {
				instf.Meta.Updated = inst.Meta.Updated
			}

			if fields.Has("spec") {

				if fields.Has("spec/meta/id") {
					instf.Spec.Meta.ID = inst.Spec.Meta.ID
				}

				if fields.Has("spec/meta/name") {
					instf.Spec.Meta.Name = inst.Spec.Meta.Name
				}

				if fields.Has("spec/meta/version") {
					instf.Spec.Meta.Version = inst.Spec.Meta.Version
				}
			}

			if fields.Has("operate") {

				if fields.Has("operate/action") {
					instf.Operate.Action = inst.Operate.Action
				}

				if fields.Has("operate/pod_id") {
					instf.Operate.PodId = inst.Operate.PodId
				}

				if fields.Has("operate/options") {

					for _, opt := range inst.Operate.Options {

						optf := &losapi.AppOption{}
						if fields.Has("operate/options/name") {
							optf.Name = opt.Name
						}

						instf.Operate.Options = append(instf.Operate.Options, optf)
					}
				}
			}

			ls.Items = append(ls.Items, instf)

		} else {
			ls.Items = append(ls.Items, inst)
		}
	}

	ls.Kind = "AppList"
}

func (c AppInst) EntryAction() {

	var app losapi.AppInstance
	if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(c.Params.Get("id"))); obj.OK() {
		obj.Decode(&app)
	}

	if app.Meta.ID == "" || app.Meta.User != c.us.UserName {
		c.RenderJson(types.NewTypeErrorMeta(losapi.ErrCodeObjectNotFound, "App Not Found"))
	} else {
		app.Kind = "App"
		c.RenderJson(app)
	}
}

func (c AppInst) SetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set losapi.AppInstance
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	var prev losapi.AppInstance

	if len(set.Meta.ID) < 8 {

		prev = set

		prev.Meta.ID = idhash.RandHexString(16)
		prev.Meta.Created = types.MetaTimeNow()
		prev.Meta.User = c.us.UserName

	} else {

		if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(set.Meta.ID)); !obj.OK() {

			if !obj.NotFound() {
				rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, "ServerError")
				return
			}

			prev = set

		} else {

			obj.Decode(&prev)

			if prev.Meta.User != c.us.UserName ||
				prev.Meta.ID != set.Meta.ID {
				rsp.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "AccessDenied")
				return
			}

			prev.Meta.Name = set.Meta.Name
			prev.Operate.ResBoundRoles = set.Operate.ResBoundRoles
			prev.Operate.Action = set.Operate.Action
		}
	}

	prev.Meta.Updated = types.MetaTimeNow()

	var spec losapi.AppSpec
	if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppSpec(prev.Spec.Meta.ID)); !obj.OK() {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	} else {
		obj.Decode(&spec)
	}

	if spec.Meta.ID == "" || spec.Meta.ID != prev.Spec.Meta.ID {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if prev.Spec.Meta.Version != spec.Meta.Version {
		prev.Spec = spec
	}

	if obj := los_db.ZoneMaster.PvPut(losapi.NsGlobalAppInstance(prev.Meta.ID), prev, &skv.PathWriteOptions{
		Force: true,
	}); !obj.OK() {
		rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	rsp.Kind = "App"
}

func (c AppInst) ListOpResAction() {

	ls := losapi.AppInstanceList{}
	defer c.RenderJson(&ls)

	if c.Params.Get("res_type") != "domain" {
		ls.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	// TODO pager
	rs := los_db.ZoneMaster.PvScan(losapi.NsGlobalAppInstance(""), "", "", 1000)
	rss := rs.KvList()
	for _, v := range rss {

		var inst losapi.AppInstance

		if err := v.Decode(&inst); err != nil {
			continue
		}

		if inst.Operate.PodId == "" {
			continue
		}

		if inst.Spec.Meta.Name != "los-httplb" &&
			inst.Spec.Meta.Name != "nginx" {
			continue
		}

		hit := false
		for _, v := range inst.Spec.ServicePorts {
			if v.Name == "http" {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}

		if inst.Meta.User == c.us.UserName ||
			inst.Operate.ResBoundRoles.MatchAny(c.us.Roles) {

			ls.Items = append(ls.Items, losapi.AppInstance{
				Meta: inst.Meta,
				Spec: losapi.AppSpec{
					Meta: types.InnerObjectMeta{
						Name: inst.Spec.Meta.Name,
					},
				},
				Operate: losapi.AppOperate{
					PodId: inst.Operate.PodId,
				},
			})
		}
	}

	ls.Kind = "AppList"
}

func (c AppInst) OpResSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set losapi.Resource
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	var res losapi.Resource
	if rs := los_db.ZoneMaster.PvGet(losapi.NsGlobalResInstance(set.Meta.Name)); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&res); err != nil {
		rsp.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if res.Meta.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	// TODO
	// if res.Operate.AppId != "" {
	// 	set.Operate.AppId = res.Operate.AppId // TODO
	// }

	//
	var app losapi.AppInstance
	if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(set.Operate.AppId)); obj.OK() {
		obj.Decode(&app)
	}
	if app.Meta.ID == "" {
		rsp.Error = types.NewErrorMeta("400", "App Not Found, or Access Denied")
		return
	}

	res_prev := app.Operate.Options.Get(res.Meta.Name)
	if res_prev != nil && res_prev.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	opt := losapi.AppOption{
		Name:    types.NewNameIdentifier("res/" + res.Meta.Name),
		User:    c.us.UserName,
		Updated: uint64(types.MetaTimeNow()),
	}
	for _, v := range res.Bounds {
		if v.Action == 1 {
			opt.Items.Set(v.Name, v.Value)
		}
	}

	if app.Operate.Options.Set(opt) {

		app.Meta.Updated = types.MetaTimeNow()

		// if res.Operate.AppId == "" { // TODO

		res.Operate.AppId = app.Meta.ID
		res.Meta.Updated = types.MetaTime(opt.Updated)

		//
		if rs := los_db.ZoneMaster.PvPut(losapi.NsGlobalResInstance(res.Meta.Name), res, &skv.PathWriteOptions{
			Force: true,
		}); !rs.OK() {
			rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, rs.Bytex().String())
			return
		}
		// }

		if obj := los_db.ZoneMaster.PvPut(losapi.NsGlobalAppInstance(app.Meta.ID), app, &skv.PathWriteOptions{
			Force: true,
		}); !obj.OK() {
			rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
			return
		}

		if app.Operate.PodId != "" &&
			app.Operate.Action == losapi.AppOperateStart {

			var pod losapi.Pod

			if rs := los_db.ZoneMaster.PvGet(losapi.NsGlobalPodInstance(app.Operate.PodId)); rs.OK() {
				rs.Decode(&pod)
				if pod.Meta.ID == app.Operate.PodId {

					pod.Apps.Sync(app)
					pod.OperateRefresh()
					pod.Meta.Updated = types.MetaTimeNow()

					if rs := los_db.ZoneMaster.PvPut(losapi.NsGlobalPodInstance(pod.Meta.ID), pod, &skv.PathWriteOptions{
						PrevVersion: rs.Meta().Version,
					}); !rs.OK() {
						rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
						return
					}

					// Pod Map to Cell Queue
					qmpath := losapi.NsZonePodSetQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
					if rs := los_db.ZoneMaster.PvPut(qmpath, pod, &skv.PathWriteOptions{
						Force: true,
					}); !rs.OK() {
						rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
						return
					}

					logger.Printf("info", "deploy app/%s to pod/%s", app.Meta.ID, pod.Meta.ID)
				}
			}
		}

		logger.Printf("info", "user/%s bound %s to app/%s", c.us.UserName, opt.Name, app.Meta.ID)
	}

	rsp.Kind = "App"
}

func (c AppInst) ConfigAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set struct {
		Id     string           `json:"id"`
		Option losapi.AppOption `json:"option"`
	}
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if len(set.Id) < 8 {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if err := set.Option.Name.Valid(); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request: "+err.Error())
		return
	}

	var app losapi.AppInstance
	if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(set.Id)); obj.OK() {
		obj.Decode(&app)
	}

	if app.Meta.ID != set.Id ||
		app.Meta.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta(losapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if app.Spec.Configurator == nil {
		rsp.Kind = "AppInstConfig"
		return
	}

	if set.Option.Name != app.Spec.Configurator.Name {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	app_op_opt := app.Operate.Options.Get(string(set.Option.Name))
	if app_op_opt == nil {
		app_op_opt = &losapi.AppOption{}
	}
	set_opt := losapi.AppOption{
		Name: set.Option.Name,
	}

	for _, field := range app.Spec.Configurator.Fields {

		value := ""

		if v, ok := set.Option.Items.Get(field.Name); ok {
			value = v.String()
		}

		for _, validator := range field.Validates {

			if re, err := regexp.Compile(validator.Key); err == nil {

				if !re.MatchString(value) {
					rsp.Error = types.NewErrorMeta("400", fmt.Sprintf("Invalid %s/Value %s", field.Name, validator.Value))
					return
				}
			}
		}

		if len(value) < 1 {
			continue
		}

		if field.Type == losapi.AppConfigFieldTypeAppOpBound {

			if len(value) < 12 {
				rsp.Error = types.NewErrorMeta("400", "No AppConfigBound Found")
				return
			}

			var app_ref losapi.AppInstance
			if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(value)); obj.OK() {
				obj.Decode(&app_ref)
			}
			if app_ref.Meta.ID != value {
				rsp.Error = types.NewErrorMeta("400", "No AppConfigBound Found")
				return
			}
			if app_ref.Meta.User != c.us.UserName {
				rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
				return
			}
			if len(app_ref.Operate.PodId) < 16 {
				rsp.Error = types.NewErrorMeta(losapi.ErrCodeObjectPending, "App in pennding")
				return
			}

			opt_ref := app_ref.Operate.Options.Get(field.Default)
			if opt_ref == nil {
				rsp.Error = types.NewErrorMeta(losapi.ErrCodeObjectNotFound, "OptionRef Not Found")
				return
			}

			if pv, ok := app_op_opt.Items.Get(field.Name); ok && len(pv.String()) >= 12 && pv.String() != value {

				if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalAppInstance(pv.String())); obj.OK() {

					var app_refp losapi.AppInstance
					obj.Decode(&app_refp)

					if app_refp.Meta.ID == pv.String() {

						if app_refp_opt := app_refp.Operate.Options.Get(field.Default); app_refp_opt != nil {

							app_refp_opt.Subs.Remove(app.Meta.ID)
							app_refp.Operate.Options.Sync(*app_refp_opt)

							if obj := los_db.ZoneMaster.PvPut(losapi.NsGlobalAppInstance(app_refp.Meta.ID), app_refp, &skv.PathWriteOptions{
								Force: true,
							}); !obj.OK() {
								rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
								return
							}

							//
							if value != app.Meta.ID {
								app.Operate.Options.Del(field.Default)
							}
						}
					}
				}
			}

			if value != app.Meta.ID {

				opt_ref.Subs.Insert(app.Meta.ID)
				app_ref.Operate.Options.Sync(*opt_ref)

				if obj := los_db.ZoneMaster.PvPut(losapi.NsGlobalAppInstance(app_ref.Meta.ID), app_ref, &skv.PathWriteOptions{
					Force: true,
				}); !obj.OK() {
					rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
					return
				}

				//
				opt_ref.Subs = []string{}
				opt_ref.Ref = &losapi.AppOptionRef{
					AppId: app_ref.Meta.ID,
					PodId: app_ref.Operate.PodId,
					Ports: app_ref.Spec.ServicePorts,
				}
				app.Operate.Options.Sync(*opt_ref)
			}
		}

		if len(value) > 0 {
			set_opt.Items.Set(field.Name, value)
		}
	}

	app.Operate.Options.Sync(set_opt)
	app.Meta.Updated = types.MetaTimeNow()

	if obj := los_db.ZoneMaster.PvPut(losapi.NsGlobalAppInstance(app.Meta.ID), app, &skv.PathWriteOptions{
		Force: true,
	}); !obj.OK() {
		rsp.Error = types.NewErrorMeta(losapi.ErrCodeServerError, obj.Bytex().String())
		return
	}

	rsp.Kind = "AppInstConfig"
}
