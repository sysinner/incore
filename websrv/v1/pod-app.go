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
	"github.com/lessos/lessgo/types"

	"github.com/hooto/iam/iamapi"
	in_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

func (c Pod) AppSyncAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	app_id := c.Params.Get("app_id")
	if app_id == "" {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	var (
		app      inapi.AppInstance
		app_sync = false
	)
	rs := in_db.ZoneMaster.PvGet(inapi.NsGlobalAppInstance(app_id))
	if rs.OK() {
		rs.Decode(&app)
	}
	if app.Meta.ID != app_id {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}
	if app.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if app.Operate.PodId == "" {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}
	if c.Params.Get("operate_action") == "start" {

		if inapi.OpActionAllow(app.Operate.Action, inapi.OpActionStart) {
			app.Operate.Action = inapi.OpActionAppend(app.Operate.Action,
				inapi.OpActionStart)
			app_sync = true
		}
	}

	//
	for i, srvport := range app.Spec.ServicePorts {

		if srvport.HostPort > 0 && srvport.HostPort <= 1024 {
			if c.us.UserName != "sysadmin" {
				set.Error = types.NewErrorMeta("403", "AccessDenied: Only SysAdmin can setting Host Port to 1~2014")
				return
			}
		} else {
			// TODO
			app.Spec.ServicePorts[i].HostPort = 0
			app_sync = true
		}
	}

	if app_sync {
		app.Meta.Updated = types.MetaTimeNow()
		if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalAppInstance(app_id), app, nil); !rs.OK() {
			set.Error = types.NewErrorMeta("500", rs.Bytex().String())
			return
		}
	}

	app.Spec.Configurator = nil

	//
	var pod inapi.Pod
	obj := in_db.ZoneMaster.PvGet(inapi.NsGlobalPodInstance(app.Operate.PodId))
	if obj.OK() {
		obj.Decode(&pod)
	}
	if pod.Meta.ID == "" ||
		pod.Meta.ID != app.Operate.PodId ||
		pod.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if pod.Spec.Zone == "" || pod.Spec.Cell == "" {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	pod.Apps.Sync(app)
	pod.Operate.Version++
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalPodInstance(pod.Meta.ID), pod, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	// Pod Map to Cell Queue
	qmpath := inapi.NsZonePodOpQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := in_db.ZoneMaster.PvPut(qmpath, pod, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	set.Kind = "App"
}

func (c Pod) AppSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	var app inapi.AppInstance
	if err := c.Request.JsonDecode(&app); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if app.Meta.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	var pod inapi.Pod
	obj := in_db.ZoneMaster.PvGet(inapi.NsGlobalPodInstance(app.Operate.PodId))
	if obj.OK() {
		obj.Decode(&pod)
	}
	if pod.Meta.ID == "" || pod.Meta.ID != app.Operate.PodId ||
		pod.Meta.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if pod.Spec.Zone == "" || pod.Spec.Cell == "" {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	for i, srvport := range app.Spec.ServicePorts {

		if srvport.HostPort > 0 && srvport.HostPort <= 1024 {
			if c.us.UserName != "sysadmin" {
				rsp.Error = types.NewErrorMeta("403", "AccessDenied: Only SysAdmin can setting Host Port to 1~2014")
				return
			}
		} else {
			// TODO
			app.Spec.ServicePorts[i].HostPort = 0
		}
	}

	app.Spec.Configurator = nil

	pod.Apps.Sync(app)
	pod.Operate.Version++
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalPodInstance(pod.Meta.ID), pod, nil); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	// Pod Map to Cell Queue
	qmpath := inapi.NsZonePodOpQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := in_db.ZoneMaster.PvPut(qmpath, pod, nil); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	rsp.Kind = "App"
}

func (c Pod) AppExecutorSetAction() {

	set := inapi.ExecutorSetup{}
	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if set.PodId == "" {
		set.Error = types.NewErrorMeta("400", "Pod Not Found 001")
		return
	}

	if set.AppId == "" {
		set.Error = types.NewErrorMeta("400", "App Not Found")
		return
	}

	if set.Spec == "" && set.Executor.Name == "" {
		set.Error = types.NewErrorMeta("400", "Executor Not Found")
		return
	}

	var (
		pod inapi.Pod
	)
	if obj := in_db.ZoneMaster.PvGet(inapi.NsGlobalPodInstance(set.PodId)); !obj.OK() {

		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	} else {
		obj.Decode(&pod)
	}

	if pod.Meta.ID != set.PodId {
		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	}

	// if pod.Meta.User != c.us.UserName {
	// 	set.Error = types.NewErrorMeta(
	// 		Code:    iamapi.ErrCodeAccessDenied,
	// 		Message: "Access Denied",
	// 	}
	// 	return
	// }

	if pod.Apps == nil {
		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	}

	if set.Spec != "" {

		spec_id := set.Spec.HashToString(16)

		var spec inapi.SpecExecutor

		if obj := in_db.ZoneMaster.PvGet(
			inapi.NsGlobalPodSpec("executor", spec_id)); !obj.OK() {
			set.Error = types.NewErrorMeta("400", "Spec Not Found")
			return
		} else {
			obj.Decode(&spec)
		}

		if spec.Meta.ID != spec_id {
			set.Error = types.NewErrorMeta("400", "Spec Not Found")
			return
		}

		set.Executor = spec.Executor
	}

	if set.Executor.Name == "" {

		if err := c.Request.JsonDecode(&set.Executor); err != nil || set.Executor.Name == "" {
			return
		}
	}

	pod.Apps.ExecutorSync(set.Executor, set.AppId)

	//
	pod.Operate.Version++
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := in_db.ZoneMaster.PvPut(inapi.NsGlobalPodInstance(set.PodId), pod, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	qmpath := inapi.NsZonePodOpQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := in_db.ZoneMaster.PvPut(qmpath, pod, nil); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	set.Kind = "Executor"
}
