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
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

var (
	podTransferEmailTemplate = `A Pod transfer issue was created by %s that to change the owner to you (%s). please login to the management console and manually confirm this issue use next URL.

Management Console: %s
Pod ID: %s

====
Please do not reply to this message. Mail sent to this address cannot be answered.
`
)

func (c Pod) UserTransferAction() {

	var (
		set  inapi.PodUserTransfer
		rsp  inapi.GeneralObject
		prev inapi.Pod
	)

	defer c.RenderJson(&rsp)

	if err := c.Request.JsonDecode(&set); err != nil {
		rsp.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(set.Id)); !rs.OK() {
		rsp.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != set.Id {
		rsp.Error = types.NewErrorMeta("400", "Prev Pod Not Found")
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
		return
	}

	if set.UserTo == prev.Meta.User {
		rsp.Kind = "PodInstance"
		return
	}

	tn := uint32(time.Now().Unix())
	if (prev.Operate.Operated + podActionQueueTimeMin) > tn {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"the previous operation is in processing, please try again later (1)")
		return
	}

	//
	if rs := data.GlobalMaster.KvGet(inapi.NsKvGlobalPodUserTransfer(prev.Meta.ID)); rs.OK() {
		var prevTransfer inapi.PodUserTransfer
		rs.Decode(&prevTransfer)
		if prevTransfer.UserTo == set.UserTo {
			rsp.Kind = "PodInstance"
			return
		}
	}

	set.Name = prev.Meta.Name
	set.UserFrom = prev.Meta.User
	set.Created = tn

	//
	if rs := data.GlobalMaster.KvPut(inapi.NsKvGlobalPodUserTransfer(set.Id),
		set, &skv.KvWriteOptions{
			Ttl: 3600e3,
		},
	); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	}

	if err := iamclient.SysMsgPost(iamapi.MsgItem{
		ToUser: set.UserTo,
		Title:  "Pod Transfer Issue Alert",
		Body: fmt.Sprintf(podTransferEmailTemplate,
			prev.Meta.User,
			set.UserTo,
			config.Config.InpanelServiceUrl,
			set.Id,
		),
	}, config.Config.ZoneIamAccessKey); err == nil {
		hlog.Printf("info", "zm/v1 msg post ok")
	} else {
		hlog.Printf("info", "zm/v1 msg post err %s", err.Error())
	}

	rsp.Kind = "PodInstance"
}

func (c Pod) UserTransferPerformAction() {

	var (
		rsp inapi.GeneralObject
		ids = strings.Split(c.Params.Get("pod_ids"), ",")
		tn  = uint32(time.Now().Unix())
	)
	defer c.RenderJson(&rsp)

	if len(ids) < 1 {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"no ids found")
		return
	}

	for _, podId := range ids {

		var (
			utp = inapi.NsKvGlobalPodUserTransfer(podId)
			it  inapi.PodUserTransfer
		)

		if rs := data.GlobalMaster.KvGet(utp); !rs.OK() {
			continue
		} else if err := rs.Decode(&it); err != nil {
			hlog.Printf("warn", "decode err %s", err.Error())
			continue
		}

		if it.UserTo != c.us.UserName {
			rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
			return
		}

		//
		var pod inapi.Pod
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(podId)); rs.OK() {
			rs.Decode(&pod)
		} else {
			rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
			return
		}

		if pod.Meta.User == it.UserTo {
			data.GlobalMaster.KvDel(utp, nil)
			continue
		}

		if pod.Meta.User != it.UserFrom ||
			pod.Spec == nil || pod.Spec.Ref.Id == "" || pod.Spec.VolSys == nil {
			rsp.Error = types.NewErrorMeta("400", "Pod Not Found")
			return
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
			rsp.Error = types.NewErrorMeta("400", "Pod Not Found")
			return
		}

		sqkey := inapi.NsKvGlobalSetQueuePod(pod.Spec.Zone, pod.Spec.Cell, pod.Meta.ID)
		if rs := data.GlobalMaster.KvGet(sqkey); rs.OK() {
			if (pod.Operate.Operated + podActionQueueTimeMin) > tn {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
					"the previous operation is in processing, please try again later (1)")
				return
			}
		}

		//
		var spec_plan inapi.PodSpecPlan
		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalPodSpec("plan",
			pod.Spec.Ref.Id)); rs.OK() {
			rs.Decode(&spec_plan)
		}
		if spec_plan.Meta.ID == "" || spec_plan.Meta.ID != pod.Spec.Ref.Id {
			rsp.Error = types.NewErrorMeta("400", "Spec Not Found")
			return
		}

		pod.Meta.User = it.UserTo
		if rsp.Error = podAccountChargePreValid(&pod, &spec_plan); rsp.Error != nil {
			return
		}

		pod.Operate.Version += 1
		pod.Meta.Updated = types.MetaTimeNow()
		pod.Operate.Operated = tn

		//
		if rs := data.GlobalMaster.PvPut(inapi.NsGlobalPodInstance(pod.Meta.ID), pod, nil); !rs.OK() {
			rsp.Error = types.NewErrorMeta("500", rs.Bytex().String())
			return
		}

		// Pod Map to Cell Queue
		data.GlobalMaster.KvPut(sqkey, pod, nil)
		data.GlobalMaster.KvDel(utp, nil)
	}

	rsp.Kind = "PodInstance"
}
