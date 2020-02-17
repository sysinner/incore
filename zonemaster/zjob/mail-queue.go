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

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/injob"
)

type MailQueue struct {
	sch  *injob.Schedule
	done int64
}

func (it *MailQueue) Name() string {
	return "zone/mail/queue"
}

func (it *MailQueue) Run(ctx *injob.Context) error {

	if !ctx.IsZoneLeader {
		return nil
	}

	if ctx.Zone == nil {
		return errors.New("invalid ctx.ZoneId")
	}

	var (
		zkey = inapi.NsZoneMailQueue("")
	)

	rs := data.DataZone.NewReader(nil).
		KeyRangeSet(zkey, zkey).
		LimitNumSet(100).
		Query()

	for _, v := range rs.Items {

		var item iamapi.MsgItem
		if err := v.Decode(&item); err != nil {
			continue
		}

		if err := iamclient.SysMsgPost(item, config.Config.ZoneIamAccessKey); err == nil {

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
