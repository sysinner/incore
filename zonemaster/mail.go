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

package zonemaster

import (
	"github.com/hooto/hmsg/go/hmsg/v1"

	inCfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

var haEmailTemplate = &hmsg.MailTemplateEntry{
	Name: "zone/pod/ha/confirm-mail",
	Items: []*hmsg.MailTemplateLang{
		{
			Lang:  "en",
			Title: "Availability Issue Alert",
			Body: `A availability issue was detected (Pod {{.PodName}}, Replica {{.ReplicaId}}) by system.
please login to the management console and manually confirm this issue and execute the failover task.

Management Console: {{.ConsoleUrl}} 

====
Please do not reply to this message. Mail sent to this address cannot be answered.
`,
			BodyType: hmsg.MsgContentType_TextPlain,
			Version:  1,
		},
		{
			Lang:  "zh-CN",
			Title: "可用性问题提醒",
			Body: `系统检测到一个可用性问题 (Pod {{.PodName}}, 副本 {{.ReplicaId}}).
请登录管理控制台核实问题并执行宕机恢复任务:

管理控制台: {{.ConsoleUrl}}

====
本邮件消息由系统自动创建，请不要回复此邮件。
`,
			BodyType: hmsg.MsgContentType_TextPlain,
			Version:  1,
		},
	},
}

func init() {
	status.ZoneMailManager.TemplateSet(haEmailTemplate)
}

type haEmailData struct {
	PodId      string
	PodName    string
	ReplicaId  uint32
	ConsoleUrl string
}

func haEmailAction(pod *inapi.Pod, repId uint32) error {

	item := haEmailData{
		ConsoleUrl: inCfg.Config.Zone.InpanelServiceUrl,
		PodId:      pod.Meta.ID,
		PodName:    pod.Meta.Name,
		ReplicaId:  repId,
	}

	mail, err := status.ZoneMailManager.TemplateRender(
		haEmailTemplate.Name, "", item)
	if err != nil {
		return err
	}

	msg := hmsg.NewMsgItem(hmsg.HashSeed(haEmailTemplate.Name + item.PodId + pod.Meta.User))
	msg.ToUser = pod.Meta.User
	msg.Title = mail.Title
	msg.Body = mail.Body
	msg.Type = mail.BodyType

	if rs := data.DataZone.NewWriter(
		inapi.NsZoneMailQueue(msg.SentId()), msg).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}
