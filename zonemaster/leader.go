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
	"time"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

// refresh zone-master leader ttl
func zmWorkerMasterLeaderRefresh() {

	if !status.IsZoneMaster() {
		return
	}

	var (
		zmLeaderKey = inapi.NsKvZoneSysMasterLeader(status.ZoneId)
	)

	if status.IsZoneMasterLeader() {

		if rs := data.DataZone.NewWriter(
			zmLeaderKey, status.Host.Meta.Id).
			PrevDataCheckSet(status.Host.Meta.Id, nil).
			ExpireSet(12000).Commit(); rs.OK() {

			status.ZoneMasterList.Version = rs.Meta.Version
			status.ZoneMasterList.Updated = rs.Meta.Updated

			hlog.Printf("debug", "zm/zone-master/leader refresh %d", rs.Meta.Version)

		} else {
			hlog.Printf("warn", "zm/zone-master/leader refresh failed %s", rs.Message)
		}

		return
	}

	if rs := data.DataZone.NewReader(zmLeaderKey).Query(); rs.NotFound() {

		if rs2 := data.DataZone.NewWriter(
			zmLeaderKey, status.Host.Meta.Id).
			PrevDataCheckSet(status.Host.Meta.Id, nil).
			ExpireSet(12000).Commit(); rs2.OK() {

			status.ZoneMasterList.Leader = status.Host.Meta.Id
			status.ZoneMasterList.Version = rs2.Meta.Version
			status.ZoneMasterList.Updated = rs2.Meta.Updated

			status.ZoneLeaded = time.Now().Unix()

			hlog.Printf("warn", "zm/zone-master/leader new node %s, version %d",
				status.Host.Meta.Id, rs2.Meta.Version)

		} else {
			hlog.Printf("warn", "zm/zone-master/leader refresh failed %s", rs2.Message)
		}

	} else if rs.OK() && len(rs.Items) > 0 {

		hostId := rs.DataValue().String()
		if inapi.ResSysHostIdReg.MatchString(hostId) &&
			(hostId != status.ZoneMasterList.Leader ||
				rs.Items[0].Meta.Version > status.ZoneMasterList.Version) {

			status.ZoneMasterList.Leader = hostId
			status.ZoneMasterList.Version = rs.Items[0].Meta.Version

			hlog.Printf("warn", "zm/zone-master/leader refresh %s, version %d",
				hostId, status.ZoneMasterList.Version)
		}

		status.ZoneMasterList.Updated = rs.Items[0].Meta.Updated

	} else {
		hlog.Printf("warn", "zm/zone-master/leader active refresh failed %s", rs.Message)
	}

}
