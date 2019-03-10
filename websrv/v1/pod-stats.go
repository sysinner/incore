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
	"encoding/base64"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type PodStats struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *PodStats) Init() int {
	c.us, _ = iamclient.SessionInstance(c.Session)
	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(
			iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}
	return 0
}

func (c *PodStats) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c PodStats) FeedAction() {

	var (
		podId          = c.Params.Get("id")
		repId          = int32(c.Params.Int64("rep_id"))
		qry            = c.Params.Get("qry")
		qry_names      = c.Params.Get("qry_names")
		qry_time_past  = uint32(c.Params.Uint64("qry_time_past"))
		qry_time_cycle = uint32(c.Params.Uint64("qry_time_cycle"))
		pod            inapi.Pod
		fq             inapi.TimeStatsFeedQuerySet
		reps           = []uint32{}
	)

	if len(qry) > 2 {
		bs, err := base64.StdEncoding.DecodeString(qry)
		if err != nil || len(bs) < 10 {
			c.RenderJson(types.NewTypeErrorMeta("400", "Bad Request"))
			return
		}

		if err := json.Decode(bs, &fq); err != nil {
			c.RenderJson(types.NewTypeErrorMeta("400", "Bad Request"))
			return
		}
	} else {
		fq.TimePast = qry_time_past
		fq.TimeCycle = qry_time_cycle
		as := strings.Split(qry_names, ",")
		for _, v := range as {

			if fq.Get(v) != nil {
				continue
			}

			fq.Items = append(fq.Items, &inapi.TimeStatsEntryQuerySet{
				Name: v,
			})
		}
	}

	if len(fq.Items) < 1 {
		c.RenderJson(types.NewTypeErrorMeta("400", "Bad Request"))
		return
	}

	fq.Fix()

	if fq.TimeStart >= fq.TimeCutset {
		c.RenderJson(types.NewTypeErrorMeta("400", "Bad Request"))
		return
	}

	if obj := data.GlobalMaster.PvGet(inapi.NsGlobalPodInstance(podId)); obj.OK() {
		obj.Decode(&pod)
		if pod.Meta.ID == "" || !c.owner_or_sysadmin_allow(pod.Meta.User, "sysinner.admin") {
			c.RenderJson(types.NewTypeErrorMeta("400", "Pod Not Found"))
			return
		}
	} else {
		c.RenderJson(types.NewTypeErrorMeta("400", "Pod Not Found"))
		return
	}

	if repId == -1 {
		for i := uint32(0); i < uint32(pod.Operate.ReplicaCap); i++ {
			reps = append(reps, i)
		}
	} else if repId < -1 || repId >= int32(pod.Operate.ReplicaCap) {
		c.RenderJson(types.NewTypeErrorMeta("400", "Invalid rep_id"))
		return
	} else {
		reps = append(reps, uint32(repId))
	}

	feed := inapi.NewPbStatsSampleFeed(fq.TimeCycle)

	// feed.Debugs.Set("time_start", fmt.Sprintf("%d", fq.TimeStart))
	// feed.Debugs.Set("time_starts", time.Unix(int64(fq.TimeStart), 0))
	// feed.Debugs.Set("time_cut", fmt.Sprintf("%d", fq.TimeCutset))
	// feed.Debugs.Set("time_cuts", time.Unix(int64(fq.TimeCutset), 0))

	for _, repId := range reps {

		if rs := data.ZoneMaster.KvScan(
			inapi.NsKvZonePodRepStats(pod.Spec.Zone, pod.Meta.ID, repId, "sys", fq.TimeStart-fq.TimeCycle-600),
			inapi.NsKvZonePodRepStats(pod.Spec.Zone, pod.Meta.ID, repId, "sys", fq.TimeCutset+600),
			50000,
		); rs.OK() {

			var (
				ls    = rs.KvList()
				ifeed inapi.PbStatsIndexFeed
				jfeed = inapi.NewPbStatsSampleFeed(fq.TimeCycle)
			)
			for _, v := range ls {

				if err := v.Decode(&ifeed); err != nil {
					continue
				}

				for _, ientry := range ifeed.Items {
					if fq.Get(ientry.Name) == nil {
						continue
					}
					for _, iv := range ientry.Items {
						if iv.Time <= fq.TimeCutset {
							jfeed.SampleSync(ientry.Name, iv.Time, iv.Value, false)
						}
					}
				}
			}

			for _, v := range jfeed.Items {
				for _, v2 := range v.Items {
					feed.SampleSync(v.Name, v2.Time, v2.Value, true)
				}
			}
		}
	}

	for _, v := range feed.Items {

		for i := fq.TimeStart; i <= fq.TimeCutset; i += fq.TimeCycle {
			v.SyncTrim(i, 0)
		}
		v.Sort()

		if len(v.Items) < 2 {
			continue
		}

		fqi := fq.Get(v.Name)
		if fqi == nil {
			continue
		}

		for i2, v2 := range v.Items {
			if v2.Value <= 0 {
				if i2 > 0 && v.Items[i2-1].Value > v2.Value {
					v.Items[i2].Value = v.Items[i2-1].Value
				}
			}
		}

		if fqi.Delta {
			last_value := int64(0)
			for i := len(v.Items) - 1; i > 0; i-- {

				if v.Items[i].Value <= 0 {
					if last_value > 0 {
						v.Items[i].Value = last_value
					}
				} else {
					last_value = v.Items[i].Value
				}

				if v.Items[i].Value >= v.Items[i-1].Value && v.Items[i-1].Value > 0 {
					v.Items[i].Value = v.Items[i].Value - v.Items[i-1].Value
				} else {
					v.Items[i].Value = 0
				}
			}
		}

		for i2, v2 := range v.Items {
			if v2.Time == fq.TimeStart {
				v.Items = v.Items[i2:]
				break
			}
		}
	}

	feed.Kind = "TimeStatsFeed"
	c.RenderJson(feed)
}
