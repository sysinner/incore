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
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/types"

	los_db "code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
)

func (c Pod) AppSetAction() {

	rsp := types.TypeMeta{}
	defer c.RenderJson(&rsp)

	var app losapi.AppInstance
	if err := c.Request.JsonDecode(&app); err != nil {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	if app.Meta.User != c.us.UserName {
		rsp.Error = types.NewErrorMeta("400", "Bad Request")
		return
	}

	//
	var pod losapi.Pod
	obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalPodInstance(app.Operate.PodId))
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
	pod.OperateRefresh()
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := los_db.ZoneMaster.PvPut(losapi.NsGlobalPodInstance(pod.Meta.ID), pod, &skv.PvWriteOptions{
		PrevVersion: obj.Meta().Version,
	}); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	// Pod Map to Cell Queue
	qmpath := losapi.NsZonePodSetQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := los_db.ZoneMaster.PvPut(qmpath, pod, &skv.PvWriteOptions{
		Force: true,
	}); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	rsp.Kind = "App"
}

func (c Pod) AppExecutorSetAction() {

	set := losapi.ExecutorSetup{}
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
		pod         losapi.Pod
		pod_version uint64
	)
	if obj := los_db.ZoneMaster.PvGet(losapi.NsGlobalPodInstance(set.PodId)); !obj.OK() {

		set.Error = types.NewErrorMeta("400", "Pod Not Found")
		return
	} else {
		obj.Decode(&pod)
		pod_version = obj.Meta().Version
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

		var spec losapi.SpecExecutor

		if obj := los_db.ZoneMaster.PvGet(
			losapi.NsGlobalPodSpec("executor", spec_id)); !obj.OK() {
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
	pod.Meta.Updated = types.MetaTimeNow()

	if rs := los_db.ZoneMaster.PvPut(losapi.NsGlobalPodInstance(set.PodId), pod, &skv.PvWriteOptions{
		PrevVersion: pod_version,
	}); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	qmpath := losapi.NsZonePodSetQueue(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
	if rs := los_db.ZoneMaster.PvPut(qmpath, pod, &skv.PvWriteOptions{
		Force: true,
	}); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	set.Kind = "Executor"
}
