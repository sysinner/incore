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

package mail_queue

import (
	"errors"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/hmsg/go/hmsg/v1"
	"github.com/hooto/iam/iamclient"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
	"github.com/sysinner/injob"
)

type MailQueue struct {
	spec *injob.JobSpec
	sch  *injob.Schedule
	done int64
}

func (it *MailQueue) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("zone/mail/queue").
			ConditionSet("zone/main-node/leader", 6000)
	}
	return it.spec
}

func (it *MailQueue) Status() *injob.Status {
	return nil
}

func (it *MailQueue) Run(ctx *injob.Context) error {

	if !status.IsZoneMasterLeader() {
		return nil
	}

	if status.Zone == nil {
		return errors.New("invalid status.ZoneId")
	}

	var (
		zkey = inapi.NsZoneMailQueue("")
	)

	rs := data.DataZone.NewReader(nil).
		KeyRangeSet(zkey, zkey).
		LimitNumSet(100).
		Query()

	for _, v := range rs.Items {

		var item hmsg.MsgItem
		if err := v.Decode(&item); err != nil {
			continue
		}

		if err := iamclient.SysMsgPost(item, config.Config.ZoneMain.IamAccessKey); err == nil {

			it.done += 1

			if rs2 := data.DataZone.NewWriter(v.Meta.Key, nil).
				ModeDeleteSet(true).Commit(); !rs2.OK() {
				hlog.Printf("info", "zm/v1 msg post clean err %s", rs2.Message)
			}

			hlog.Printf("info", "zm/v1 msg post %s to %s ok", item.Id, item.ToUser)
		} else {
			hlog.Printf("info", "zm/v1 msg post err %s", err.Error())
		}
	}

	if len(rs.Items) > 0 {
		hlog.Printf("info", "zm/v1 msg post num %d", it.done)
	}

	return nil
}

func NewMailQueueJobEntry() *injob.JobEntry {
	return injob.NewJobEntry(&MailQueue{},
		injob.NewSchedule().EveryTimeCycle(injob.Second, 10))
}
