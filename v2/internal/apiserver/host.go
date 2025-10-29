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

package apiserver

import (
	"github.com/lynkdb/lynkapi/go/lynkapi"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
	inapi2 "github.com/sysinner/incore/v2/inapi"
)

func (it *ApiService) HostZoneList(
	ctx lynkapi.Context,
	req *inapi2.HostService_ZoneListRequest,
) (*inapi2.HostService_ZoneListResponse, error) {

	rsp := &inapi2.HostService_ZoneListResponse{}

	if !status.IsZoneMaster() {
		return nil, lynkapi.NewClientError("Invalid Zone MainNode Address")
	}

	for _, v := range status.GlobalZones {

		zone := &inapi2.HostService_Zone{
			Meta: &inapi2.Common_Meta{
				Id: v.Meta.Id,
			},
			Description: v.Summary,
			Action:      inapi.OpActionString(v.Phase),
			/**
			LanAddrs:           v.LanAddrs,
			WanApi:             v.WanApi,
			Phase:              v.Phase,
			NetworkDomainName:  v.NetworkDomainName,
			NetworkVpcBridge:   v.NetworkVpcBridge,
			NetworkVpcInstance: v.NetworkVpcInstance,
			*/
		}

		rsp.Zones = append(rsp.Zones, zone)
	}

	return rsp, nil
}
