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
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	iox_utils "github.com/lynkdb/iomix/utils"
	kv2 "github.com/lynkdb/kvspec/v2/go/kvspec"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
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
	if c.us.AccessAllow(user) ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.Zone.InstanceId) {
		return true
	}
	return false
}

func (c App) ListAction() {

	ls := inapi.AppInstanceList{}
	defer c.RenderJson(&ls)

	// TODO pager
	rs := data.DataGlobal.NewReader(nil).ModeRevRangeSet(true).
		KeyRangeSet(inapi.NsGlobalAppInstance("zzzzzzzz"), inapi.NsGlobalAppInstance("")).
		LimitNumSet(10000).Query()

	var fields types.ArrayPathTree
	if fns := c.Params.Value("fields"); fns != "" {
		fields.Set(fns)
		fields.Sort()
	}

	for _, v := range rs.Items {

		var inst inapi.AppInstance

		if err := v.Decode(&inst); err != nil {
			continue
		}

		// TOPO
		if c.Params.Value("filter_meta_user") == "all" &&
			iamclient.SessionAccessAllowed(c.Session, "sysinner.admin", config.Config.Zone.InstanceId) {
			//
		} else if !c.us.AccessAllow(inst.Meta.User) {
			continue
		}

		// auto fix
		if inapi.OpActionAllow(inst.Operate.Action, inapi.OpActionDestroy) {
			if v.Meta == nil || v.Meta.Expired == 0 {
				if rs := data.DataGlobal.NewWriter(inapi.NsKvGlobalAppInstanceDestroyed(inst.Meta.ID), inst).Commit(); rs.OK() {
					data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(inst.Meta.ID), inst).
						ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
				}
			}
			continue
		}

		if c.Params.Value("spec_id") != "" {
			if inst.Spec.Meta.ID != c.Params.Value("spec_id") {
				continue
			}
		}

		if c.Params.Value("qry_text") != "" &&
			!strings.Contains(inst.Meta.Name, c.Params.Value("qry_text")) {
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

			ls.Items = append(ls.Items, &instf)

		} else {
			ls.Items = append(ls.Items, &inst)
		}
	}

	ls.Kind = "AppList"
}

func (c App) EntryAction() {

	var app inapi.AppInstance
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(c.Params.Value("id"))).Query(); rs.OK() {
		rs.Decode(&app)
	}

	appOpOptRender(&app, true)

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

		if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(set.Meta.ID)).Query(); rs.OK() {
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

	spec := appSpecVersionLastPatch(prev.Spec.Meta.ID, prev.Spec.Meta.Version)

	if spec == nil {
		if set_new {
			rsp.Error = types.NewErrorMeta("400", fmt.Sprintf("AppSpec Not Found %s/%s", prev.Spec.Meta.ID, prev.Spec.Meta.Version))
			return
		}
	} else {
		prev.Spec = *spec
		hlog.Printf("info", "app spec %s, version %s", spec.Meta.ID, spec.Meta.Version)
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		prev.Operate.Action = prev.Operate.Action | inapi.OpActionStop
	}

	var rs *kv2.ObjectResult

	if set_new {

		if prev.Operate.PodId == "" {
			rsp.Error = types.NewErrorMeta("400", "Operate.PodId Not Bound")
			return
		}

		var pod inapi.Pod
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(prev.Operate.PodId)).Query(); !rs.OK() {
			rsp.Error = types.NewErrorMeta("500", "Server Error")
			return
		} else {
			rs.Decode(&pod)
		}

		if pod.Meta.ID != prev.Operate.PodId {
			rsp.Error = types.NewErrorMeta("400", "Operate.PodId Not Found")
			return
		}

		if err := appPodConflictCheck(&pod, &prev); err != nil {
			rsp.Error = types.NewErrorMeta("400", err.Error())
			return
		}

		if err := appPodResCheck(&pod, prev.Spec.ExpRes); err != nil {
			rsp.Error = types.NewErrorMeta("400", err.Error()+", try to select another pod to deploy this application")
			return
		}

		rs = data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(prev.Meta.ID), prev).ModeCreateSet(true).Commit()
	} else {

		rs = data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(prev.Meta.ID), prev).Commit()
	}

	if !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
		return
	}

	if deploy {
		if rsp.Error = appInstDeploy(prev); rsp.Error != nil {
			return
		}
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		if rs := data.DataGlobal.NewWriter(inapi.NsKvGlobalAppInstanceDestroyed(prev.Meta.ID), prev).Commit(); rs.OK() {
			rs = data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(prev.Meta.ID), prev).
				ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
		}
	}
	rsp.Meta.ID = prev.Meta.ID
	rsp.Kind = "App"
}

func appPodResCheck(pod *inapi.Pod, app_spec_res *inapi.AppSpecResRequirements) error {

	if pod.Spec == nil {
		return errors.New("this pod currently unavailable")
	}

	if app_spec_res == nil {
		app_spec_res = &inapi.AppSpecResRequirements{}
	}

	if pod.Spec.VolSys == nil {
		return errors.New("pod currently unavailable")
	} else if app_spec_res.VolMin > pod.Spec.VolSys.Size {
		return fmt.Errorf("AppSpec requires at least %d GiB sytem volume space",
			app_spec_res.VolMin)
	}

	res := pod.Spec.ResComputeBound()

	if app_spec_res.CpuMin > res.CpuLimit {
		return fmt.Errorf("AppSpec requires at least %d CPU resource",
			app_spec_res.CpuMin)
	}

	if app_spec_res.MemMin > res.MemLimit {
		return fmt.Errorf("AppSpec requires at least %d MB Memory space",
			app_spec_res.MemMin)
	}

	return nil
}

func appPodConflictCheck(pod *inapi.Pod, app *inapi.AppInstance) error {

	if app.Spec.ExpDeploy == nil {
		app.Spec.ExpDeploy = &inapi.AppSpecExpDeployRequirements{}
	}

	if app.Spec.ExpDeploy.SysState == inapi.AppSpecExpDeploySysStateful &&
		pod.Operate.ExpSysState == inapi.AppSpecExpDeploySysStateless {
		return errors.New(
			"conflict of State settings between AppSpec:Stateful and Pod:Stateless")
	}

	for _, v := range pod.Apps {

		if app.Meta.ID == v.Meta.ID {
			continue
		}

		if v.Spec.Meta.ID == app.Spec.Meta.ID &&
			!inapi.OpActionAllow(v.Operate.Action, inapi.OpActionDestroy) {
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

		for _, vr := range app.Spec.VcsRepos {
			for _, vr2 := range v.Spec.VcsRepos {
				if vr.Dir == vr2.Dir {
					return fmt.Errorf(
						"conflict of AppSpec/VcsRepo. another app (%s) had bound the vcs repo (%s) to pod (%s)",
						v.Meta.ID, vr.Dir, app.Operate.PodId)
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

	if c.Params.Value("res_type") != "domain" {
		ls.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	// TODO pager
	rs := data.DataGlobal.NewReader(nil).KeyRangeSet(
		inapi.NsGlobalAppInstance(""), inapi.NsGlobalAppInstance("")).
		LimitNumSet(1000).Query()
	for _, v := range rs.Items {

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

			ls.Items = append(ls.Items, &inapi.AppInstance{
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
		app_id    = c.Params.Value("app_id")
		op_action = uint32(c.Params.IntValue("op_action"))
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(app_id)).Query(); rs.OK() {
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

		if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(app.Meta.ID), app).Commit(); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
			return
		}
	}

	if rsp.Error = appInstDeploy(app); rsp.Error != nil {
		return
	}

	if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionDestroy) {
		if rs := data.DataGlobal.NewWriter(inapi.NsKvGlobalAppInstanceDestroyed(app.Meta.ID), app).Commit(); rs.OK() {
			data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(app.Meta.ID), app).
				ExpireSet(inapi.PodDestroyTTL * 1000).Commit()
		}
	}

	rsp.Kind = "App"
}

func appInstDeploy(app inapi.AppInstance) *types.ErrorMeta {

	if app.Operate.PodId == "" {
		return nil
	}

	var pod inapi.Pod
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(app.Operate.PodId)).Query(); !rs.OK() {
		return types.NewErrorMeta("500", rs.Message)
	} else {
		rs.Decode(&pod)
	}

	if pod.Meta.ID != app.Operate.PodId {
		return types.NewErrorMeta("404", "No Pod Found")
	}

	if hit := inapi.SliceFind(app.Spec.RuntimeImages, func(i int) bool {
		return app.Spec.RuntimeImages[i] == pod.Spec.Box.Image.Ref.Id
	}); hit == nil {
		return types.NewErrorMeta(inapi.ErrCodeBadArgument,
			fmt.Sprintf("The Runtime Image of Pod(%s) and AppSpec (%s) do not match",
				pod.Spec.Box.Image.Ref.Id, strings.Join(app.Spec.RuntimeImages, ",")))
	}

	appOpOptRender(&app, false)

	pod.Apps.Sync(&app)
	pod.Operate.Version++
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(pod.Meta.ID), pod).Commit(); !rs.OK() {
		return types.NewErrorMeta("500", rs.Message)
	}

	// Pod Map to Cell Queue
	sqkey := inapi.NsKvGlobalSetQueuePod(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := data.DataGlobal.NewWriter(sqkey, pod).Commit(); !rs.OK() {
		return types.NewErrorMeta("500", rs.Message)
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalResInstance(set.Meta.Name)).Query(); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Message)
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(set.Operate.AppId)).Query(); rs.OK() {
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
		Updated: types.MetaTimeNow(),
	}
	for _, v := range res.Bounds {
		if v.Action != 1 {
			continue
		}

		item := &inapi.AppOptionField{
			Name:  v.Name,
			Value: v.Value,
			// Type:  v.Type,
		}

		if ls, _ := inapi.SliceMerge(opt.Items, item, func(i int) bool {
			return opt.Items[i].Name == item.Name
		}); ls != nil {
			opt.Items = ls.([]*inapi.AppOptionField)
		}

		//
		if !strings.HasPrefix(v.Value, "pod:") {
			continue
		}

		ar := strings.Split(v.Value, ":")
		if len(ar) != 3 {
			continue
		}

		if !inapi.PodIdReg.MatchString(ar[1]) {
			continue
		}

		port, _ := strconv.Atoi(ar[2])
		if port < 1 || port > 65535 {
			continue
		}

		app.Operate.BindServices, _ = inapi.AppServicePortSliceSync(app.Operate.BindServices, &inapi.AppServicePort{
			Port:  uint32(port),
			PodId: ar[1],
		})
	}

	for _, v := range res.Options {

		item := &inapi.AppOptionField{
			Name:  "option/" + v.Name,
			Value: v.Value,
		}

		if ls, _ := inapi.SliceMerge(opt.Items, item, func(i int) bool {
			return opt.Items[i].Name == item.Name
		}); ls != nil {
			opt.Items = ls.([]*inapi.AppOptionField)
		}
	}

	if app.Operate.Options.Set(opt) {

		app.Meta.Updated = types.MetaTimeNow()

		// if res.Operate.AppId == "" { // TODO

		res.Operate.AppId = app.Meta.ID
		res.Meta.Updated = types.MetaTime(opt.Updated)

		//
		if rs := data.DataGlobal.NewWriter(inapi.NsGlobalResInstance(res.Meta.Name), res).Commit(); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
			return
		}
		// }

		if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(app.Meta.ID), app).Commit(); !rs.OK() {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
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
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(set.Id)).Query(); rs.OK() {
		rs.Decode(&app)
	}

	if app.Meta.ID != set.Id ||
		!c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	var appConfigurator *inapi.AppConfigurator

	if app.Spec.Configurator != nil &&
		app.Spec.Configurator.Name == set.Option.Name {
		appConfigurator = app.Spec.Configurator
	} else {

		for _, v := range app.Spec.Depends {

			if v.Id != set.SpecId {
				continue
			}

			app_spec := appSpecVersionLastPatch(v.Id, v.Version)
			if app_spec == nil {
				continue
				// rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, fmt.Sprintf("AppSpec (%s) Not Found", v.Id))
			}

			if app_spec.Configurator != nil && len(app_spec.Configurator.Fields) > 0 {
				appConfigurator = app_spec.Configurator
			}

			break
		}
	}

	if appConfigurator == nil {
		rsp.Kind = "AppInstConfig"
		return
	}

	if set.Option.Name != appConfigurator.Name {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	appOpOpt := app.Operate.Options.Get(string(set.Option.Name))
	if appOpOpt == nil {
		appOpOpt = &inapi.AppOption{}
	}
	set_opt := inapi.AppOption{
		Name: set.Option.Name,
	}

	for _, field := range appConfigurator.Fields {

		var (
			value      = ""
			value_prev = ""
		)
		if v, ok := set.Option.ValueOK(field.Name); ok {
			value = v.String()
		}
		if v, ok := appOpOpt.ValueOK(field.Name); ok {
			value_prev = v.String()
		}

		if field.AutoFill != "" {

			switch field.AutoFill {

			case inapi.AppConfigFieldAutoFillDefaultValue:
				if len(field.Default) < 1 {
					rsp.Error = types.NewErrorMeta("400", "DefaultValue empty")
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
				rsp.Error = types.NewErrorMeta("500", "Not DedaultValue Type Found")
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

		if len(value) > 0 {
			item := &inapi.AppOptionField{
				Name:  field.Name,
				Value: value,
				Type:  field.Type,
			}
			if ls, _ := inapi.SliceMerge(set_opt.Items, item, func(i int) bool {
				return set_opt.Items[i].Name == item.Name
			}); ls != nil {
				set_opt.Items = ls.([]*inapi.AppOptionField)
			}
		}
	}

	app.Operate.Options.Sync(set_opt)
	app.Meta.Updated = types.MetaTimeNow()

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(app.Meta.ID), app).Commit(); !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
		return
	}

	rsp.Kind = "AppInstConfig"
}

func (c App) ConfigRepRemotesAction() {

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

	var app inapi.AppInstance
	if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(set.Id)).Query(); rs.OK() {
		rs.Decode(&app)
	}

	if len(set.DepRemotes) == 0 || len(app.Spec.DepRemotes) == 0 {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if app.Meta.ID != set.Id ||
		!c.owner_or_sysadmin_allow(app.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	for _, v := range set.DepRemotes {

		//
		depRemote := inapi.AppSpecDependSliceGet(app.Spec.DepRemotes, v.SpecId)
		if depRemote == nil {
			rsp.Error = types.NewErrorMeta("400",
				fmt.Sprintf("No AppSpec:%s Found", v.SpecId))
			return
		}

		//
		var refApp inapi.AppInstance
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(v.AppId)).Query(); rs.OK() {
			rs.Decode(&refApp)
		}
		if refApp.Meta.ID != v.AppId {
			rsp.Error = types.NewErrorMeta("400",
				fmt.Sprintf("No AppInstance %s Found", v.AppId))
			return
		}
		if !c.owner_or_sysadmin_allow(refApp.Meta.User, "sysinner.admin") {
			rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
			return
		}
		if len(refApp.Operate.PodId) < 16 {
			rsp.Error = types.NewErrorMeta(inapi.ErrCodeObjectPending,
				fmt.Sprintf("AppInstance %s is not ready, try again later", v.AppId))
			return
		}
		if len(refApp.Spec.ServicePorts) < 1 {
			rsp.Error = types.NewErrorMeta("400",
				fmt.Sprintf("No Service Found in App %s", v.AppId))
			return
		}

		//
		for _, cfgName := range depRemote.Configs {

			refAppOpt := refApp.Operate.Options.Get(cfgName)
			if refAppOpt == nil {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeObjectNotFound,
					fmt.Sprintf("AppInstance %s, Option %s Not Found", v.AppId, cfgName))
				return
			}

			optRefCfg := app.Operate.Options.Get(cfgName)

			// clean prev settings
			if optRefCfg != nil && optRefCfg.Ref != nil && (optRefCfg.Ref.AppId != v.AppId || v.Delete) {

				if rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(optRefCfg.Ref.AppId)).Query(); rs.OK() {

					var refAppPrev inapi.AppInstance
					rs.Decode(&refAppPrev)

					if refAppPrev.Meta.ID == optRefCfg.Ref.AppId {

						if refAppPrevOpt := refAppPrev.Operate.Options.Get(cfgName); refAppPrevOpt != nil {

							refAppPrevOpt.Subs.Del(app.Meta.ID)
							refAppPrev.Operate.Options.Sync(*refAppPrevOpt)

							if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(refAppPrev.Meta.ID), refAppPrev).Commit(); !rs.OK() {
								rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
								return
							}
						}
					}
				}
			}

			if v.Delete {

				ls := inapi.AppOptions{}
				for _, v2 := range app.Operate.Options {
					if v2.Ref == nil || v2.Ref.SpecId != v.SpecId || v2.Ref.AppId != v.AppId {
						ls = append(ls, v2)
					}
				}
				if len(ls) < len(app.Operate.Options) {
					app.Operate.Options = ls
				}
				continue
			}

			//
			refAppOpt.Subs.Set(app.Meta.ID)
			refApp.Operate.Options.Sync(*refAppOpt)
			if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(refApp.Meta.ID), refApp).Commit(); !rs.OK() {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
				return
			}

			//
			refAppOpt.Subs = []string{}
			refAppOpt.Ref = &inapi.AppOptionRef{
				SpecId: depRemote.Id,
				AppId:  refApp.Meta.ID,
				PodId:  refApp.Operate.PodId,
			}
			app.Operate.Options.Sync(*refAppOpt)
		}

		// TODO clean refApp*
		if v.Delete {
			for i2, v2 := range app.Operate.Services {
				if v.AppId == v2.AppId && v.SpecId == v2.Spec {
					app.Operate.Services = append(app.Operate.Services[:i2], app.Operate.Services[i2+1:]...)
					break
				}
			}
			continue
		}

		//
		for _, vsp := range refApp.Spec.ServicePorts {
			spSet := &inapi.AppServicePort{
				Spec:  refApp.Spec.Meta.ID,
				Port:  uint32(vsp.BoxPort),
				Name:  vsp.Name,
				PodId: refApp.Operate.PodId,
				AppId: v.AppId,
			}
			if srv := inapi.AppServicePortSliceGet(app.Operate.Services, uint32(vsp.BoxPort), refApp.Operate.PodId); srv == nil {
				app.Operate.Services, _ = inapi.AppServicePortSliceSync(app.Operate.Services, spSet)
			} else {
				srv.Sync(spSet)
			}
		}
	}

	app.Meta.Updated = types.MetaTimeNow()

	if rs := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(app.Meta.ID), app).Commit(); !rs.OK() {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeServerError, rs.Message)
		return
	}

	rsp.Kind = "AppInstConfig"
}

var exArr = map[string]string{}

func appOpOptRender(app *inapi.AppInstance, specRender bool) {

	if len(exArr) == 0 {
		exArr["xcs_sysinner_iam_service_url"] = iamclient.ServiceUrl
		exArr["xcs_sysinner_iam_service_url_frontend"] = iamclient.ServiceUrlFrontend
	}

	for _, v := range app.Operate.Options {
		for _, v2 := range v.Items {
			if strings.Index(v2.Value, "{{.") < 0 ||
				(v2.Type >= 300 || v2.Type <= 399) {
				continue
			}
			if tpl, err := template.New("s").Parse(v2.Value); err == nil {
				var dst bytes.Buffer
				if err := tpl.Execute(&dst, exArr); err == nil {
					item := &inapi.AppOptionField{
						Name:  v2.Name,
						Type:  v2.Type,
						Value: dst.String(),
					}
					if ls, _ := inapi.SliceMerge(v.Items, item, func(i int) bool {
						return v.Items[i].Name == item.Name
					}); ls != nil {
						v.Items = ls.([]*inapi.AppOptionField)
					}
				}
			}
		}
	}

	if specRender && app.Spec.Configurator != nil {
		for _, v := range app.Spec.Configurator.Fields {
			if strings.Index(v.Default, "{{.") < 0 ||
				(v.Type >= 300 || v.Type <= 399) {
				continue
			}
			if tpl, err := template.New("s").Parse(v.Default); err == nil {
				var dst bytes.Buffer
				if err := tpl.Execute(&dst, exArr); err == nil {
					v.Default = dst.String()
				}
			}
		}
	}
}
