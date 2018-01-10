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
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"
	iox_utils "github.com/lynkdb/iomix/utils"

	"github.com/sysinner/incore/config"
	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type App struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *App) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c *App) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c App) ListAction() {

	ls := inapi.AppInstanceList{}
	defer c.RenderJson(&ls)

	// TODO pager
	rs := in_db.ZoneMaster.PvRevScan(inapi.NsGlobalAppInstance(""), "", "", 10000)
	rss := rs.KvList()

	var fields types.ArrayPathTree
	if fns := c.Params.Get("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rss {

		var inst inapi.AppInstance

		if err := v.Decode(&inst); err != nil {
			continue
		}

		// TOPO
		if c.Params.Get("filter_meta_user") == "all" &&
			iamclient.SessionAccessAllowed(c.Session, "sysinner.admin", config.Config.InstanceId) {
			//
		} else if inst.Meta.User != c.us.UserName {
			continue
		}

		// UPGRADE 0.3.5 to 0.3.6
		if inapi.OpActionAllow(inst.Operate.Action, inapi.OpActionDestroy) {
			if m := v.Meta(); m == nil || m.Expired == 0 {
				if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstanceDestroyed(inst.Meta.ID), inst, nil); rs.OK() {
					in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(inst.Meta.ID), inst, &skv.ProgWriteOptions{
						Expired: time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second),
					})
				}
			}
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

			instf := inapi.AppInstance{
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

						optf := &inapi.AppOption{}
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

func (c App) EntryAction() {

	var app inapi.AppInstance
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(c.Params.Get("id"))); rs.OK() {
		rs.Decode(&app)
	}

	app_operate_option_render(&app, true)

	if app.Meta.ID == "" || !c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin") {
		c.RenderJson(types.NewTypeErrorMeta(inapi.ErrCodeObjectNotFound, "App Not Found"))
	} else {
		app.Kind = "App"
		c.RenderJson(app)
	}
}

func (c App) SetAction() {

	var rsp struct {
		types.TypeMeta `json:",inline"`
		Meta           types.InnerObjectMeta `json:"meta,omitempty"`
	}
	defer c.RenderJson(&rsp)

	//
	var set inapi.AppInstance
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	var (
		prev    inapi.AppInstance
		deploy  = false
		tn      = types.MetaTimeNow()
		set_new = false
	)

	if len(set.Meta.ID) < 8 {

		prev = set

		prev.Meta.ID = iox_utils.Uint32ToHexString(uint32(time.Now().Unix())) + idhash.RandHexString(8)
		prev.Meta.Created = tn
		prev.Meta.User = c.us.UserName
		set_new = true

	} else {

		if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(set.Meta.ID)); rs.OK() {
			rs.Decode(&prev)
		}

		if prev.Meta.ID != set.Meta.ID || !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}

		if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
			rsp.Error = types.NewErrorMeta("400", "the app instance has been destroyed")
			return
		}

		prev.Meta.Name = set.Meta.Name
		prev.Operate.ResBoundRoles = set.Operate.ResBoundRoles

		if set.Spec.Meta.Version != "" && set.Spec.Meta.Version != prev.Spec.Meta.Version {
			prev.Spec.Meta.Version = set.Spec.Meta.Version
		}

		if set.Operate.Action > 0 &&
			inapi.OpActionValid(set.Operate.Action) &&
			prev.Operate.Action != set.Operate.Action {
			prev.Operate.Action = set.Operate.Action
			deploy = true
		}
	}

	prev.Meta.Updated = tn

	var rs *skv.Result
	if prev.Spec.Meta.Version != "" {
		rs = in_db.ZoneMaster.ProgGet(inapi.NsGlobalAppSpecVersion(prev.Spec.Meta.ID, prev.Spec.Meta.Version))
	} else {
		rs = in_db.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(prev.Spec.Meta.ID))
	}
	var spec inapi.AppSpec
	if rs.OK() {
		rs.Decode(&spec)
	}

	if spec.Meta.ID == "" || spec.Meta.ID != prev.Spec.Meta.ID {
		rsp.Error = types.NewErrorMeta("400", fmt.Sprintf("AppSpec Not Found %s/%s", prev.Spec.Meta.ID, prev.Spec.Meta.Version))
		return
	}

	prev.Spec = spec

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		prev.Operate.Action = prev.Operate.Action | inapi.OpActionStop
	}

	if set_new {

		if prev.Operate.PodId == "" {
			rsp.Error = types.NewErrorMeta("400", "Operate.PodId Not Bound")
			return
		}

		var pod inapi.Pod
		if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalPodInstance(prev.Operate.PodId)); !rs.OK() {
			rsp.Error = types.NewErrorMeta("500", "Server Error")
			return
		} else {
			rs.Decode(&pod)
		}

		if pod.Meta.ID != prev.Operate.PodId {
			rsp.Error = types.NewErrorMeta("400", "Operate.PodId Not Found")
			return
		}

		if err := app_pod_conflict_check(&pod, &prev); err != nil {
			rsp.Error = types.NewErrorMeta("400", err.Error())
			return
		}

		if err := app_pod_res_check(&pod, &prev.Spec.ExpRes); err != nil {
			rsp.Error = types.NewErrorMeta("400", err.Error()+", try to select another pod to deploy this application")
			return
		}

		rs = in_db.ZoneMaster.PvNew(inapi.NsGlobalAppInstance(prev.Meta.ID), prev, nil)
	} else {
		rs = in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(prev.Meta.ID), prev, nil)
	}

	if !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	if deploy {
		if rsp.Error = appInstDeploy(prev); rsp.Error != nil {
			return
		}
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstanceDestroyed(prev.Meta.ID), prev, nil); rs.OK() {
			rs = in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(prev.Meta.ID), prev, &skv.ProgWriteOptions{
				Expired: time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second),
			})
		}
	}
	rsp.Meta.ID = prev.Meta.ID
	rsp.Kind = "App"
}

func app_pod_res_check(pod *inapi.Pod, app_spec_res *inapi.AppSpecResRequirements) error {

	if pod.Spec == nil {
		return errors.New("this pod currently unavailable")
	}

	if vol := pod.Spec.Volume("system"); vol == nil {
		return errors.New("pod currently unavailable")
	} else if app_spec_res.VolMin > vol.SizeLimit {
		return fmt.Errorf("AppSpec requires at least %0.1f GB sytem volume space",
			float64(app_spec_res.VolMin)/float64(inapi.ByteGB))
	}

	res := pod.Spec.ResComputeBound()
	if app_spec_res.CpuMin > res.CpuLimit {
		return fmt.Errorf("AppSpec requires at least %d m CPU resource",
			app_spec_res.CpuMin)
	}

	if app_spec_res.MemMin > res.MemLimit {
		return fmt.Errorf("AppSpec requires at least %d MB Memory space",
			app_spec_res.MemMin/inapi.ByteMB)
	}

	return nil
}

func app_pod_conflict_check(pod *inapi.Pod, app *inapi.AppInstance) error {

	for _, v := range pod.Apps {

		if app.Meta.ID == v.Meta.ID {
			continue
		}

		if v.Spec.Meta.ID == app.Spec.Meta.ID {
			return fmt.Errorf(
				"conflict of AppSpec. another app (%s) has been bound to pod (%s)",
				v.Meta.ID, app.Operate.PodId)
		}

		for _, p := range app.Spec.Packages {
			for _, p2 := range v.Spec.Packages {
				if p.Name == p2.Name {
					return fmt.Errorf(
						"conflict of AppSpec/Package. another app (%s) had bound the package (%s) to pod (%s)",
						v.Meta.ID, p.Name, app.Operate.PodId)
				}
			}
		}

		for _, e := range app.Spec.Executors {
			for _, e2 := range v.Spec.Executors {
				if e.Name == e2.Name {
					return fmt.Errorf(
						"conflict of AppSpec/Executor. another app (%s) had bound the executor (%s) to pod (%s)",
						v.Meta.ID, e.Name, app.Operate.PodId)
				}
			}
		}

		for _, sp := range app.Spec.ServicePorts {
			for _, sp2 := range v.Spec.ServicePorts {
				if sp.Name == sp2.Name || sp.BoxPort == sp2.BoxPort {
					return fmt.Errorf(
						"conflict of AppSpec/ServicePort. another app (%s) had bound the port (%s/%d) to pod (%s)",
						v.Meta.ID, sp2.Name, sp2.BoxPort, app.Operate.PodId)
				}
			}
		}
	}

	return nil
}

func (c App) ListOpResAction() {

	ls := inapi.AppInstanceList{}
	defer c.RenderJson(&ls)

	if c.Params.Get("res_type") != "domain" {
		ls.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	// TODO pager
	rs := in_db.ZoneMaster.PvScan(inapi.NsGlobalAppInstance(""), "", "", 1000)
	rss := rs.KvList()
	for _, v := range rss {

		var inst inapi.AppInstance

		if err := v.Decode(&inst); err != nil {
			continue
		}

		if inst.Operate.PodId == "" {
			continue
		}

		if inst.Spec.Meta.ID != "sysinner-httplb" &&
			inst.Spec.Meta.ID != "nginx" {
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

			ls.Items = append(ls.Items, inapi.AppInstance{
				Meta: inst.Meta,
				Spec: inapi.AppSpec{
					Meta: types.InnerObjectMeta{
						ID:      inst.Spec.Meta.ID,
						Name:    inst.Spec.Meta.Name,
						Version: inst.Spec.Meta.Version,
					},
				},
				Operate: inapi.AppOperate{
					PodId: inst.Operate.PodId,
				},
			})
		}
	}

	ls.Kind = "AppList"
}

func (c App) OpActionSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	var (
		app_id    = c.Params.Get("app_id")
		op_action = uint32(c.Params.Uint64("op_action"))
	)

	if !inapi.AppIdRe2.MatchString(app_id) {
		rsp.Error = types.NewErrorMeta("400", "Invalid AppInstance ID")
		return
	}

	if !inapi.OpActionAllow(
		inapi.OpActionStart|inapi.OpActionStop|inapi.OpActionDestroy,
		op_action,
	) {
		rsp.Error = types.NewErrorMeta("400", "Invalid OpAction")
		return
	}

	//
	var app inapi.AppInstance
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(app_id)); rs.OK() {
		rs.Decode(&app)
	}
	if app.Meta.ID != app_id ||
		!c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta("400", "App Not Found, or Access Denied")
		return
	}

	if app.Operate.PodId == "" {
		rsp.Error = types.NewErrorMeta("400", "No Pod Bound")
		return
	}

	if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionDestroy) {
		rsp.Error = types.NewErrorMeta("400", "the app instance has been destroyed")
		return
	}

	if inapi.OpActionAllow(op_action, inapi.OpActionDestroy) {
		op_action = op_action | inapi.OpActionStop
	}

	if app.Operate.Action != op_action {

		app.Operate.Action = op_action
		app.Meta.Updated = types.MetaTimeNow()

		if rs := in_db.ZoneMaster.PvPut(
			inapi.NsGlobalAppInstance(app.Meta.ID), app, nil,
		); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
			return
		}
	}

	if rsp.Error = appInstDeploy(app); rsp.Error != nil {
		return
	}

	if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionDestroy) {
		if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstanceDestroyed(app.Meta.ID), app, nil); rs.OK() {
			in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app.Meta.ID), app, &skv.ProgWriteOptions{
				Expired: time.Now().Add(time.Duration(inapi.PodDestroyTTL) * time.Second),
			})
		}
	}

	rsp.Kind = "App"
}

func appInstDeploy(app inapi.AppInstance) *types.ErrorMeta {

	if app.Operate.PodId == "" {
		return nil
	}

	var pod inapi.Pod
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalPodInstance(app.Operate.PodId)); !rs.OK() {
		return types.NewErrorMeta("500", rs.Bytex().String())
	} else {
		rs.Decode(&pod)
	}

	if pod.Meta.ID != app.Operate.PodId {
		return types.NewErrorMeta("404", "No Pod Found")
	}

	app_operate_option_render(&app, false)

	pod.Apps.Sync(app)
	pod.Operate.Version++
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalPodInstance(pod.Meta.ID), pod, nil); !rs.OK() {
		return types.NewErrorMeta("500", rs.Bytex().String())
	}

	// Pod Map to Cell Queue
	qmpath := inapi.NsZonePodOpQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := in_db.ZoneMaster.PvPut(qmpath, pod, nil); !rs.OK() {
		return types.NewErrorMeta("500", rs.Bytex().String())
	}

	hlog.Printf("info", "deploy app/%s to pod/%s", app.Meta.ID, pod.Meta.ID)

	return nil
}

func (c App) OpResSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set inapi.Resource
	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	var res inapi.Resource
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalResInstance(set.Meta.Name)); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&res); err != nil {
		rsp.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if !c.owner_or_sysadmin_allow(res.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	// TODO
	// if res.Operate.AppId != "" {
	// 	set.Operate.AppId = res.Operate.AppId // TODO
	// }

	//
	var app inapi.AppInstance
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(set.Operate.AppId)); rs.OK() {
		rs.Decode(&app)
	}
	if app.Meta.ID == "" ||
		(!app.Operate.ResBoundRoles.MatchAny(c.us.Roles) &&
			!c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin")) {
		rsp.Error = types.NewErrorMeta("400", "App Not Found, or Access Denied")
		return
	}

	// res_prev := app.Operate.Options.Get(res.Meta.Name)
	// if res_prev != nil && res_prev.User != res.Meta.User {
	// 	rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
	// 	return
	// }

	opt := inapi.AppOption{
		Name:    types.NewNameIdentifier("res/" + res.Meta.Name),
		User:    res.Meta.User,
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
		if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalResInstance(res.Meta.Name), res, nil); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
			return
		}
		// }

		if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app.Meta.ID), app, nil); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
			return
		}

		if app.Operate.PodId != "" &&
			inapi.OpActionAllow(app.Operate.Action, inapi.OpActionStart) {

			if rsp.Error = appInstDeploy(app); rsp.Error != nil {
				return
			}
		}

		hlog.Printf("info", "user/%s bound %s to app/%s", c.us.UserName, opt.Name, app.Meta.ID)
	}

	rsp.Kind = "App"
}

func (c App) ConfigAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	//
	var set inapi.AppConfigSet
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

	var app inapi.AppInstance
	if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(set.Id)); rs.OK() {
		rs.Decode(&app)
	}

	if app.Meta.ID != set.Id ||
		!c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	var app_configurator *inapi.AppConfigurator

	if app.Spec.Configurator != nil &&
		app.Spec.Configurator.Name == set.Option.Name {
		app_configurator = app.Spec.Configurator
	} else {
		for _, v := range app.Spec.Depends {

			if v.Id != set.SpecId {
				continue
			}

			var app_spec inapi.AppSpec
			if rs := in_db.ZoneMaster.ProgGet(inapi.NsGlobalAppSpecVersion(v.Id, v.Version)); rs.OK() {
				rs.Decode(&app_spec)
			}
			if app_spec.Meta.ID != v.Id { // TODO
				if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppSpec(v.Id)); rs.OK() {
					rs.Decode(&app_spec)
				}
			}
			if app_spec.Configurator != nil && len(app_spec.Configurator.Fields) > 0 {
				app_configurator = app_spec.Configurator
			}

			break
		}
	}

	if app_configurator == nil {
		rsp.Kind = "AppInstConfig"
		return
	}

	if set.Option.Name != app_configurator.Name {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	app_op_opt := app.Operate.Options.Get(string(set.Option.Name))
	if app_op_opt == nil {
		app_op_opt = &inapi.AppOption{}
	}
	set_opt := inapi.AppOption{
		Name: set.Option.Name,
	}

	for _, field := range app_configurator.Fields {

		var (
			value      = ""
			value_prev = ""
		)
		if v, ok := set.Option.Items.Get(field.Name); ok {
			value = v.String()
		}
		if v, ok := app_op_opt.Items.Get(field.Name); ok {
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

		if len(value) < 1 {
			continue
		}

		if field.Type == inapi.AppConfigFieldTypeAppOpBound {

			if len(value) < 12 {
				rsp.Error = types.NewErrorMeta("400", "No AppConfigBound Found")
				return
			}

			var app_ref inapi.AppInstance
			if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(value)); rs.OK() {
				rs.Decode(&app_ref)
			}
			if app_ref.Meta.ID != value {
				rsp.Error = types.NewErrorMeta("400", "No AppConfigBound Found")
				return
			}
			if !c.owner_or_sysadmin_allow(app_ref.Meta.User, "sysinner.admin") {
				rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
				return
			}
			if len(app_ref.Operate.PodId) < 16 {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeObjectPending, "App in pennding")
				return
			}

			opt_ref := app_ref.Operate.Options.Get(field.Default)
			if opt_ref == nil {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound, "OptionRef Not Found")
				return
			}

			if pv, ok := app_op_opt.Items.Get(field.Name); ok && len(pv.String()) >= 12 && pv.String() != value {

				if rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(pv.String())); rs.OK() {

					var app_refp inapi.AppInstance
					rs.Decode(&app_refp)

					if app_refp.Meta.ID == pv.String() {

						if app_refp_opt := app_refp.Operate.Options.Get(field.Default); app_refp_opt != nil {

							app_refp_opt.Subs.Remove(app.Meta.ID)
							app_refp.Operate.Options.Sync(*app_refp_opt)

							if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app_refp.Meta.ID), app_refp, nil); !rs.OK() {
								rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
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

				if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app_ref.Meta.ID), app_ref, nil); !rs.OK() {
					rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
					return
				}

				//
				opt_ref.Subs = []string{}
				opt_ref.Ref = &inapi.AppOptionRef{
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

	if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app.Meta.ID), app, nil); !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Bytex().String())
		return
	}

	rsp.Kind = "AppInstConfig"
}

var ex_arr = map[string]string{}

func app_operate_option_render(app *inapi.AppInstance, spec_render bool) {
	if len(ex_arr) == 0 {
		ex_arr["xcs_sysinner_iam_service_url"] = iamclient.ServiceUrl
		ex_arr["xcs_sysinner_iam_service_url_frontend"] = iamclient.ServiceUrlFrontend
	}

	for _, v := range app.Operate.Options {
		for _, v2 := range v.Items {
			if strings.Index(v2.Value, "{{.") < 0 {
				continue
			}
			if tpl, err := template.New("s").Parse(v2.Value); err == nil {
				var dst bytes.Buffer
				if err := tpl.Execute(&dst, ex_arr); err == nil {
					v.Items.Set(v2.Name, dst.String())
				}
			}
		}
	}

	if spec_render && app.Spec.Configurator != nil {
		for _, v := range app.Spec.Configurator.Fields {
			if strings.Index(v.Default, "{{.") < 0 {
				continue
			}
			if tpl, err := template.New("s").Parse(v.Default); err == nil {
				var dst bytes.Buffer
				if err := tpl.Execute(&dst, ex_arr); err == nil {
					v.Default = dst.String()
				}
			}
		}
	}
}
