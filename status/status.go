// Copyright 2015 Authors, All rights reserved.
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

package status

import (
	"errors"

	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
)

var (
	Prefix string
	Host   = inapi.ResHost{
		Meta:    &inapi.ObjectMeta{},
		Operate: &inapi.ResHostOperate{},
		Spec:    &inapi.ResHostSpec{},
		Status:  &inapi.ResHostStatus{},
	}
	LocalZoneMasterList inapi.ResZoneMasterList

	//
	ZoneId               string
	Zone                 *inapi.ResZone
	ZoneMasterList       inapi.ResZoneMasterList
	ZoneHostList         inapi.ResHostList
	ZoneHostListImported = false
	ZoneHostSecretKeys   types.KvPairs
)

func IsZoneMaster() bool {

	for _, v := range LocalZoneMasterList.Items {

		if v.Id == Host.Meta.Id {
			return true
		}
	}

	return false
}

func IsZoneMasterLeader() bool {
	return LocalZoneMasterList.Leader == Host.Meta.Id
}

func Init() error {

	if len(config.Config.Host.Id) < 16 {
		return errors.New("No Config Found")
	}

	Prefix = config.Prefix

	Host = inapi.ResHost{
		Meta: &inapi.ObjectMeta{
			Id: config.Config.Host.Id,
		},
		Operate: &inapi.ResHostOperate{
			Action: 1,
			ZoneId: config.Config.Host.ZoneId,
		},
		Spec: &inapi.ResHostSpec{
			PeerLanAddr: string(config.Config.Host.LanAddr),
			PeerWanAddr: string(config.Config.Host.WanAddr),
		},
		Status: &inapi.ResHostStatus{
			Uptime: uint64(types.MetaTimeNow()),
		},
	}

	ZoneId = config.Config.Host.ZoneId

	return nil
}
