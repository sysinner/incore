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
	"time"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

type PodRep struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *PodRep) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c *PodRep) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c PodRep) SetAction() {

	set := types.TypeMeta{}
	defer c.RenderJson(&set)

	if config.Config.ZoneMaster == nil ||
		!config.Config.ZoneMaster.MultiHostEnable ||
		!config.Config.ZoneMaster.MultiReplicaEnable {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Access Denied")
		return
	}

	var item inapi.PodRep

	if err := c.Request.JsonDecode(&item); err != nil {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Request JSON")
		return
	}

	if !inapi.PodIdReg.MatchString(item.Meta.ID) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Pod ID")
		return
	}

	if item.Replica.RepId > 65535 {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Rep ID")
		return
	}

	if !inapi.OpActionValid(item.Replica.Action) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Invalid Replica/Action")
		return
	}

	var (
		podGlobalKey = inapi.NsGlobalPodInstance(item.Meta.ID)
		prev         inapi.Pod
	)
	if rs := data.GlobalMaster.PvGet(podGlobalKey); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument, "Pod Not Found")
		return
	} else {
		rs.Decode(&prev)
	}

	if prev.Meta.ID != item.Meta.ID ||
		!c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"Pod Not Found or Access Denied")
		return
	}

	if inapi.OpActionAllow(prev.Operate.Action, inapi.OpActionDestroy) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"the pod instance has been destroyed")
		return
	}

	if item.Replica.RepId >= uint32(prev.Operate.ReplicaCap) {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"Invalid Replica ID")
		return
	}

	tn := uint32(time.Now().Unix())
	if tn-prev.Operate.Operated < podActionSetTimeMin {
		set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
			"too many operations in 1 minute, try again later")
		return
	}

	// Pod Map to Cell Queue
	podQueueKey := inapi.NsKvGlobalSetQueuePod(prev.Spec.Zone, prev.Spec.Cell, prev.Meta.ID)
	if rs := data.GlobalMaster.KvGet(podQueueKey); rs.OK() {
		if tn-prev.Operate.Operated < podActionQueueTimeMin {
			set.Error = types.NewErrorMeta(inapi.ErrCodeBadArgument,
				"the previous operation is in processing, please try again later")
			return
		}
	}

	prev.Operate.Version++
	prev.Operate.Operated = tn

	if rs := data.GlobalMaster.PvPut(podGlobalKey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError,
			"server error, please try again later")
		return
	}

	if inapi.OpActionAllow(item.Replica.Action, inapi.OpActionMigrate) {
		prev.Operate.RepMigrates = []uint32{
			item.Replica.RepId,
		}
	}

	if rs := data.GlobalMaster.KvPut(podQueueKey, prev, nil); !rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeServerError,
			"server error, please try again later")
		return
	}

	set.Kind = "PodRep"
}
