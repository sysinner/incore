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
	"errors"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/hmsg/go/hmsg/v1"
	"github.com/hooto/iam/iamapi"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/injob"
)

type PodStatusMail struct {
	spec *injob.JobSpec
	sch  *injob.Schedule
}

func (it *PodStatusMail) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("zone/pod/status/mail").
			ConditionSet("zone/main/leader", -1)
	}
	return it.spec
}

func (it *PodStatusMail) Status() *injob.Status {
	return nil
}

func (it *PodStatusMail) Run(ctx *injob.Context) error {

	if !ctx.IsZoneLeader {
		return nil
	}

	if ctx.Zone == nil {
		return errors.New("no ctx.ZoneId setup")
	}

	if ctx.ZonePodStatusList == nil ||
		len(ctx.ZonePodStatusList.Items) < 1 {
		return errors.New("no ctx.ZonePodStatusList setup")
	}

	if ctx.ZoneMailManager == nil {
		return errors.New("no ctx.ZoneMailManager setup")
	}

	if err := ctx.ZoneMailManager.TemplateSet(podStatusMailTemplate); err != nil {
		return err
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
				PodName:            pod.Meta.Name,
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

		mail, err := ctx.ZoneMailManager.TemplateRender(
			podStatusMailTemplate.Name, "", set)
		if err != nil {
			return err
		}

		msg := hmsg.NewMsgItem(hmsg.HashSeed(it.Spec().Name + user))
		msg.ToUser = user
		msg.Title = mail.Title
		msg.Body = mail.Body
		msg.Type = mail.BodyType
		msg.Created = tn

		if rs := data.DataZone.NewWriter(
			inapi.NsZoneMailQueue(msg.SentId()), msg).Commit(); !rs.OK() {
			return rs.Error()
		}
	}

	hlog.Printf("info", "job %s, n %d", it.Spec().Name, len(rs.Items))

	return nil
}

func NewPodStatusMailJobEntry() *injob.JobEntry {
	return injob.NewJobEntry(&PodStatusMail{},
		injob.NewSchedule().EveryTime(injob.Weekday, 1))
}
