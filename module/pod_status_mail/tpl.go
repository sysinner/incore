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

package pod_status_mail

import (
	"github.com/hooto/hmsg/go/hmsg/v1"
)

var podStatusMailTemplate = &hmsg.MailTemplateEntry{
	Name: "pod/status/mail",
	Items: []*hmsg.MailTemplateLang{
		{
			Lang:  "en",
			Title: "Pod Status Weekly (the {{.WeekNum}} week)",
			Body: `<html>
<body style="margin: 0; padding: 0; line-height: 200%;">

<table border="0" cellpadding="0" cellspacing="0" width="100%">
<tr><td>

  <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
 
	<tr><td style="font-size:160%;">
      <h3>Pod Status of Weekly (the {{.WeekNum}} week)</h3>
    </td></tr>
    
    {{range $v := .Items}}
	<tr><td style="padding-top:1em;font-size:160%;">
      Pod {{$v.PodName}}
    </td></tr>
    <tr><td>
      <table width="100%">
        <tr>
          <td>ID</td>
          <td>{{$v.PodId}}</td>
        </tr>
        <tr>
          <td>Zone/Type</td>
          <td>{{$v.ZoneName}} / {{$v.CellName}}</td>
        </tr>
        <tr>
          <td>CPU/RAM</td>
          <td>{{$v.SpecCpu}} m / {{$v.SpecMem}} MB</td>
        </tr>
        <tr>
          <td>Storage</td>
          <td>{{$v.SpecVol}} GB</td>
        </tr>
        <tr>
          <td>Usage of Storage</td>
          <td>
            {{range $v2 := $v.Reps}}
			<div>Replica #{{$v2.Id}} : {{$v2.VolUsed}} MB</div>
            {{end}}
          </td>
        </tr>
        <tr>
          <td>Cost in running</td>
          <td>{{$v.PaymentCycleAmount}}/hour</td>
        </tr>
      </table>
    </td></tr>
    {{end}}
    
     
	<tr><td style="padding-top:1em;">
      <span style="font-size:120%; font-weight:bold;">Notice</span>
      <span>this message was auto created by InnerStack, please do not reply to this message. Mail sent to this address cannot be answered.</span>
    </td></tr>
    
  </table>


</td></tr>
</table>

</body>
</html>
`,
			BodyType: hmsg.MsgContentType_TextHtml,
			Version:  1,
		},
		{
			Lang:  "zh-CN",
			Title: "Pod 状态周报(第{{.WeekNum}}周)",
			Body: `<html>
<body style="margin: 0; padding: 0; line-height: 200%;">

<table border="0" cellpadding="0" cellspacing="0" width="100%">
<tr><td>

  <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
  
	<tr><td style="font-size:160%;">
      <h3>Pod 状态周报(第{{.WeekNum}}周)</h3>
    </td></tr>
    
    {{range $v := .Items}}
	<tr><td style="padding-top:1em;font-size:160%;">
      Pod {{$v.PodName}}
    </td></tr>
    <tr><td>
      <table width="100%">
        <tr>
          <td>ID</td>
          <td>{{$v.PodId}}</td>
        </tr>
        <tr>
          <td>区域/类型</td>
          <td>{{$v.ZoneName}} / {{$v.CellName}}</td>
        </tr>
        <tr>
          <td>CPU/RAM 配额</td>
          <td>{{$v.SpecCpu}} m / {{$v.SpecMem}} MB</td>
        </tr>
        <tr>
          <td>存储配额</td>
          <td>{{$v.SpecVol}} GB</td>
        </tr>
        <tr>
          <td>存储使用</td>
          <td>
            {{range $v2 := $v.Reps}}
			<div>副本 #{{$v2.Id}} : {{$v2.VolUsed}} MB</div>
            {{end}}
          </td>
        </tr>
        <tr>
          <td>运行成本</td>
          <td>{{$v.PaymentCycleAmount}}/小时</td>
        </tr>
      </table>
    </td></tr>
    {{end}}
    
     
	<tr><td style="padding-top:1em;">
      <span style="font-size:120%; font-weight:bold;">注意</span>
      <span>本邮件消息由系统自动创建，请不要回复此邮件。</span>
    </td></tr>
    
  </table>


</td></tr>
</table>

</body>
</html>
`,
			BodyType: hmsg.MsgContentType_TextHtml,
			Version:  1,
		},
	},
}
