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
	"github.com/hooto/hmsg/go/hmsg/v1"
	"github.com/hooto/iam/iamapi"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var podTransferEmailTemplate = &hmsg.MailTemplateEntry{
	Name: "zone/pod/transfer/confirm-mail",
	Items: []*hmsg.MailTemplateLang{
		{
			Lang:  "en",
			Title: "Pod Transfer Issue Alert",
			Body: `A Pod transfer issue was created by {{.FromUser}} that to change the owner to you ({{.ToUser}}).
please login to the management console and manually confirm this issue use next URL.

Management Console: {{.ConsoleUrl}}
Pod ID: {{.PodId}}
Pod Name: {{.PodName}}

====
Please do not reply to this message. Mail sent to this address cannot be answered.
`,
			BodyType: hmsg.MsgContentType_TextPlain,
			Version:  1,
		},
		{
			Lang:  "zh-CN",
			Title: "Pod 所有权转移提醒",
			Body: `有一个 Pod 转移工单已经被 {{.FromUser}} 创建, 它会将 Pod 所有人变更为你 ({{.ToUser}}), 
请登录管理控制台确认这项操作:

管理控制台: {{.ConsoleUrl}}
Pod ID: {{.PodId}}
Pod 名称: {{.PodName}}

====
本邮件消息由系统自动创建，请不要回复此邮件。
`,
			BodyType: hmsg.MsgContentType_TextPlain,
			Version:  1,
		},
	},
}

func init() {
	status.ZoneMailManager.TemplateSet(podTransferEmailTemplate)
}

type userTransferData struct {
	ToUser     string
	FromUser   string
	ConsoleUrl string
	PodId      string
	PodName    string
}

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

	if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(set.Id)).Query(); !rs.OK() {
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
	tl := prev.Operate.Operated + podActionQueueTimeMin
	if tl > tn {
		rsp.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			fmt.Sprintf("the operations is too frequent, please try again later (%d seconds)", tl-tn))
		return
	}

	//
	if rs := data.DataGlobal.NewReader(inapi.NsKvGlobalPodUserTransfer(prev.Meta.ID)).Query(); rs.OK() {
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
	if rs := data.DataGlobal.NewWriter(inapi.NsKvGlobalPodUserTransfer(set.Id), set).
		ExpireSet(3600 * 1000).Commit(); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	item := userTransferData{
		FromUser:   prev.Meta.User,
		ToUser:     set.UserTo,
		ConsoleUrl: config.Config.Zone.InpanelServiceUrl,
		PodId:      set.Id,
		PodName:    set.Name,
	}

	mail, err := status.ZoneMailManager.TemplateRender(
		podTransferEmailTemplate.Name, "", item)
	if err != nil {
		rsp.Error = types.NewErrorMeta("500", err.Error())
		return
	}

	msg := hmsg.NewMsgItem(hmsg.HashSeed(podTransferEmailTemplate.Name + item.PodId + item.ToUser))
	msg.ToUser = item.ToUser
	msg.Title = mail.Title
	msg.Body = mail.Body
	msg.Type = mail.BodyType

	if rs := data.DataZone.NewWriter(
		inapi.NsZoneMailQueue(msg.SentId()), msg).Commit(); !rs.OK() {
		rsp.Error = types.NewErrorMeta("500", rs.Message)
		return
	}

	rsp.Kind = "PodInstance"
}

func (c Pod) UserTransferPerformAction() {

	var (
		rsp inapi.GeneralObject
		ids = strings.Split(c.Params.Value("pod_ids"), ",")
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

		if rs := data.DataGlobal.NewReader(utp).Query(); !rs.OK() {
			continue
		} else if err := rs.Decode(&it); err != nil {
			hlog.Printf("warn", "decode err %s", err.Error())
			continue
		}

		if !c.us.AccessAllow(it.UserTo) {
			rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
			return
		}

		//
		var pod inapi.Pod
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodInstance(podId)).Query(); rs.OK() {
			rs.Decode(&pod)
		} else {
			rsp.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "Access Denied")
			return
		}

		if pod.Meta.User == it.UserTo {
			data.DataGlobal.NewWriter(utp, nil).ModeDeleteSet(true).Commit()
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
		if rs := data.DataGlobal.NewReader(sqkey).Query(); rs.OK() {
			if (pod.Operate.Operated + podActionQueueTimeMin) > tn {
				rsp.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
					"the previous operation is in processing, please try again later (1)")
				return
			}
		}

		//
		var spec_plan inapi.PodSpecPlan
		if rs := data.DataGlobal.NewReader(inapi.NsGlobalPodSpec("plan",
			pod.Spec.Ref.Id)).Query(); rs.OK() {
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

		if err := c.userTransferPerformApp(&pod); err != nil {
			rsp.Error = types.NewErrorMeta("500", err.Error())
			return
		}

		pod.Operate.Version += 1
		pod.Meta.Updated = types.MetaTimeNow()
		pod.Operate.Operated = tn

		//
		if rs := data.DataGlobal.NewWriter(inapi.NsGlobalPodInstance(pod.Meta.ID), pod).Commit(); !rs.OK() {
			rsp.Error = types.NewErrorMeta("500", rs.Message)
			return
		}

		//
		// Pod Map to Cell Queue
		data.DataGlobal.NewWriter(sqkey, pod).Commit()
		data.DataGlobal.NewWriter(utp, nil).ModeDeleteSet(true).Commit()
	}

	rsp.Kind = "PodInstance"
}

func (c Pod) userTransferPerformApp(set *inapi.Pod) error {

	for i, v := range set.Apps {

		if v.Meta.User == set.Meta.User {
			continue
		}

		rs := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(v.Meta.ID)).Query()
		if rs.NotFound() {
			continue
		} else if !rs.OK() {
			return rs.Error()
		}
		//
		var app inapi.AppInstance
		if err := rs.Decode(&app); err != nil {
			return err
		}
		if app.Meta.ID != v.Meta.ID {
			continue
		}

		for _, v2 := range v.Operate.Services {

			if v2.AppId == "" || v2.AppId == v.Meta.ID {
				continue
			}

			rs2 := data.DataGlobal.NewReader(inapi.NsGlobalAppInstance(v2.AppId)).Query()
			if rs2.NotFound() {
				continue
			} else if !rs2.OK() {
				return rs2.Error()
			}

			var app2 inapi.AppInstance
			if err := rs2.Decode(&app2); err != nil {
				return err
			}
			if app2.Meta.ID != v2.AppId ||
				app2.Meta.User == set.Meta.User {
				continue
			}

			hlog.Printf("warn", "App %s, transfer owner from %s to %s",
				v2.AppId, app2.Meta.User, set.Meta.User)

			app2.Meta.User = set.Meta.User
			if rs2 = data.DataGlobal.NewWriter(
				inapi.NsGlobalAppInstance(v2.AppId), app2).Commit(); !rs2.OK() {
				return rs2.Error()
			}
		}

		if app.Meta.User == set.Meta.User {
			continue
		}

		hlog.Printf("warn", "App %s, transfer owner from %s to %s",
			v.Meta.ID, app.Meta.User, set.Meta.User)

		app.Meta.User = set.Meta.User
		rs2 := data.DataGlobal.NewWriter(inapi.NsGlobalAppInstance(v.Meta.ID), app).Commit()
		if !rs2.OK() {
			return rs2.Error()
		}

		set.Apps[i].Meta.User = set.Meta.User
	}

	return nil
}
