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

package zjob

import (
	"errors"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/lessos/lessgo/crypto/idhash"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inapi/job"
	"github.com/sysinner/incore/inutils/tplrender"
)

var (
	podStatusMailTemplate = &inapi.MailTemplate{
		Name:  "pod/status/mail",
		Title: "Pod Status of Week {{.WeekNum}}",
		Body: `<html>
<body>

<h2>Pod Status of Week {{.WeekNum}}</h2>
<div>
<table cellpadding="5" align="left">
<thead>
<tr>
<th>Pod</th>
<th>Location</th>
<th>CPU/RAM</th>
<th>Storage</th>
<th>Storage Usage of Replicas</th>
<th>Cost in running</th>
</tr>
</thead>
<tbody>
{{range $v := .Items}}
<tr>
<td>{{$v.PodId}}</td>
<td>{{$v.ZoneName}} / {{$v.CellName}}</td>
<td>{{$v.SpecCpu}} m / {{$v.SpecMem}} MB</td>
<td>{{$v.SpecVol}} GB</td>
<td>
{{range $v2 := $v.Reps}}
<div>#{{$v2.Id}} {{$v2.VolUsed}} MB</div>
{{end}}
</td>
<td>{{$v.PaymentCycleAmount}}/Hour</td>
</tr>
{{end}}
</tbody>
</table>
</div>

<h2>Notice</h2>
<div>
this message was auto created by InnerStack, please do not reply to this message. Mail sent to this address cannot be answered.
</div>
</body>
</html>
`,
		Type: inapi.MailType_HTML,
	}
)

type PodStatusMail struct {
	sch *job.Schedule
}

func (it *PodStatusMail) Name() string {
	return "zone/pod/status/mail"
}

func (it *PodStatusMail) Run(ctx *job.Context) error {

	if !ctx.IsZoneLeader {
		return nil
	}

	if ctx.Zone == nil {
		return errors.New("invalid ctx.ZoneId")
	}

	if ctx.ZonePodStatusList == nil ||
		len(ctx.ZonePodStatusList.Items) < 1 {
		return errors.New("invalid ctx.ZonePodStatusList")
	}

	var (
		userPods = map[string][]*inapi.Pod{}
		zkey     = inapi.NsZonePodInstance(ctx.Zone.Meta.Id, "")
	)

	rs := data.DataZone.NewReader(nil).
		KeyRangeSet(zkey, zkey).
		LimitNumSet(10000).
		Query()

	for _, v := range rs.Items {

		var pod inapi.Pod
		if err := v.Decode(&pod); err != nil {
			continue
		}

		if inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionDestroy) {
			continue
		}

		userPods[pod.Meta.User] = append(userPods[pod.Meta.User], &pod)
	}

	var (
		t     = time.Now()
		_, wn = t.ISOWeek()
		tn    = uint32(t.Unix())
	)

	for user, pods := range userPods {

		set := inapi.MailPodStatus{
			User:    user,
			Created: tn,
			WeekNum: uint32(wn),
		}

		for _, pod := range pods {

			item := &inapi.MailPodStatus_Pod{
				PodId:              pod.Meta.ID,
				ZoneName:           pod.Spec.Zone,
				CellName:           pod.Spec.Cell,
				SpecCpu:            pod.Spec.Box.Resources.CpuLimit * 100,
				SpecMem:            pod.Spec.Box.Resources.MemLimit,
				SpecVol:            pod.Spec.VolSys.Size,
				PaymentCycleAmount: float32(iamapi.AccountFloat64Round(pod.Payment.CycleAmount, 2)),
			}

			ps := ctx.ZonePodStatusList.Get(pod.Meta.ID)
			if ps != nil {

				for _, rep := range ps.Replicas {

					itemRep := &inapi.MailPodStatus_PodReplica{
						Id:      rep.RepId,
						VolUsed: 0,
					}

					for _, rv := range rep.Volumes {
						if rv.MountPath == "/home/action" {
							itemRep.VolUsed = rv.Used / inapi.ByteMB
						}
					}

					item.Reps = append(item.Reps, itemRep)
				}
			}

			set.Items = append(set.Items, item)
		}

		tbs, err := tplrender.Render(podStatusMailTemplate.Title, set)
		if err != nil {
			return err
		}

		bbs, err := tplrender.Render(podStatusMailTemplate.Body, set)
		if err != nil {
			return err
		}

		msg := iamapi.MsgItem{
			Id:      idhash.HashToHexString([]byte(it.Name()+user), 16),
			Created: tn,
			ToUser:  user,
			Title:   string(tbs),
			Body:    string(bbs),
			Type:    iamapi.MsgType(podStatusMailTemplate.Type),
		}

		if rs := data.DataZone.NewWriter(
			inapi.NsZoneMailQueue(msg.SentId()), msg).Commit(); !rs.OK() {
			return rs.Error()
		}
	}

	hlog.Printf("info", "job %s, n %d", it.Name(), len(rs.Items))

	return nil
}

func NewPodStatusMailJobEntry() *job.JobEntry {
	return job.NewJobEntry(&PodStatusMail{},
		job.NewSchedule().EveryTime(job.Dow, 1))
}
