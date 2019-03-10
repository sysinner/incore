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

package status

import (
	"errors"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/iam/iamapi"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
)

var (
	inited bool = false

	// local host
	Host = inapi.ResHost{
		Meta:    &inapi.ObjectMeta{},
		Operate: &inapi.ResHostOperate{},
		Spec:    &inapi.ResHostSpec{},
		Status:  &inapi.ResHostStatus{},
	}
	LocalZoneMasterList inapi.ResZoneMasterList

	// local zone
	ZoneId               string
	Zone                 *inapi.ResZone
	ZoneMasterList       inapi.ResZoneMasterList
	ZoneHostList         inapi.ResHostList
	ZoneHostListImported = false
	ZoneHostSecretKeys   types.KvPairs
	ZonePodList          = inapi.PodList{}
	ZonePodStatusList    = inapi.PodStatusList{}
	ZonePodServices      struct {
		Items []*inapi.AppServicePod `json:"items"`
	}
	zonePodChargeIamAccessKey = iamapi.AccessKey{
		User: "sysadmin",
	}
	ZoneSysConfigGroupList inapi.SysConfigGroupList

	// local cell

	// global cluster
	GlobalZones    []*inapi.ResZone
	GlobalHostList inapi.ResHostList
)

func GlobalZone(zoneId string) *inapi.ResZone {
	for _, v := range GlobalZones {
		if v.Meta.Id == zoneId {
			return v
		}
	}
	return nil
}

func GlobalZoneCell(zoneId, cellId string) *inapi.ResCell {
	if zone := GlobalZone(zoneId); zone != nil {
		for _, v := range zone.Cells {
			if v.Meta.Id == cellId {
				return v
			}
		}
	}
	return nil
}

func ZonePodChargeAccessKey() iamapi.AccessKey {

	if Zone != nil && len(zonePodChargeIamAccessKey.AccessKey) < 8 {

		if v, ok := Zone.OptionGet("iam/acc_charge/access_key"); ok {
			zonePodChargeIamAccessKey.AccessKey = v
		}

		if v, ok := Zone.OptionGet("iam/acc_charge/secret_key"); ok {
			zonePodChargeIamAccessKey.SecretKey = v
		}
	}

	return zonePodChargeIamAccessKey
}

func IsZoneMaster() bool {
	for _, v := range config.Config.Masters {
		if v == config.Config.Host.LanAddr {
			return true
		}
	}
	return false
}

func IsZoneMasterLeader() bool {
	return ZoneMasterList.Leader == Host.Meta.Id
}

func ZoneMasters() []string {
	zms := []string{}
	for _, v := range ZoneMasterList.Items {
		zms = append(zms, v.Addr)
	}
	return zms
}

func Init() error {

	if len(config.Config.Host.Id) < 16 {
		return errors.New("No Config Found")
	}

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
			Uptime: uint32(time.Now().Unix()),
		},
	}

	ZoneId = config.Config.Host.ZoneId

	if config.IsZoneMaster() {
		json.DecodeFile(config.Prefix+"/etc/zm-pod-services.json", &ZonePodServices)
		hlog.Printf("info", "status/zone/pod/service refreshed %d", len(ZonePodServices.Items))
	}

	inited = true

	return nil
}

func ZonePodServicesFlush() {
	json.EncodeToFile(ZonePodServices, config.Prefix+"/etc/zm-pod-services.json", "  ")
}

func HostletReady() bool {
	return inited
}

func ZoneHostIp(hostId string) string {
	if host := ZoneHostList.Item(hostId); host != nil {
		lanAddr := host.Spec.PeerLanAddr
		if i := strings.IndexByte(lanAddr, ':'); i > 0 {

			return lanAddr[:i]
		}
	}
	return ""
}
