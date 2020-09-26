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

package hostlet

import (
	"errors"

	"github.com/hooto/hlog4g/hlog"
	"golang.org/x/net/context"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/status"
)

type ApiHostMember struct {
	inapi.UnimplementedApiHostMemberServer
}

func (s *ApiHostMember) HostJoin(
	ctx context.Context,
	opts *inapi.ResHostNew,
) (*inapi.ResHost, error) {

	if !status.HostletReady() {
		return nil, errors.New("service unavailable, please try again later")
	}

	if opts == nil ||
		len(config.Config.Zone.MainNodes) > 0 {
		return nil, errors.New("Action Denied: the host only to perform a one-time initialization to join one cluster")
	}

	if len(opts.ZoneMasters) < 1 {
		return nil, errors.New("Invalid Zone Masters")
	}

	if !inapi.HostNodeAddress(opts.PeerLanAddr).Valid() {
		return nil, errors.New("Peer LAN Address Not Valid")
	}

	if opts.PeerLanAddr != string(config.Config.Host.LanAddr) {
		return nil, errors.New("Invalid Peer Lan Address")
	}

	if !inapi.ResSysHostSecretKeyReg.MatchString(opts.SecretKey) ||
		opts.SecretKey != config.Config.Host.SecretKey {
		return nil, errors.New("Invalid Secret Key")
	}

	mainNodes := []string{}
	for _, v := range opts.ZoneMasters {
		addr := inapi.HostNodeAddress(v)
		if !addr.Valid() {
			return nil, errors.New("Invalid Zone Masters: " + v)
		}
		mainNodes = inapi.ArrayStringUniJoin(mainNodes, addr.String())
	}

	config.Config.Zone.ZoneId = opts.ZoneId
	config.Config.Zone.MainNodes = mainNodes

	status.Host.Operate.ZoneId = opts.ZoneId
	status.ZoneId = opts.ZoneId

	config.Config.Host.ZoneId = opts.ZoneId
	config.Config.Zone.InpackServiceUrl = opts.ZoneInpackServiceUrl

	status.ZoneHostSecretKeys.Set(status.Host.Meta.Id, config.Config.Host.SecretKey)

	config.Config.Flush()
	hlog.Printf("warn", "zone-master node join zone:%s", config.Config.Host.ZoneId)

	return &status.Host, nil
}
