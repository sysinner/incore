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
	"strings"
	"time"

	"github.com/hooto/httpsrv"

	"github.com/sysinner/incore/inagent/status"
	"github.com/sysinner/incore/inapi"
)

type Health struct {
	*httpsrv.Controller
}

func (c Health) SyncAction() {

	var (
		action = strings.ToLower(c.Params.Get("action"))
	)

	switch action {
	case "active":
		status.HealthStatus.Action = inapi.HealthStatusActionActive

	case "setup":
		status.HealthStatus.Action = inapi.HealthStatusActionSetup

	default:
		c.RenderString("ER")
		return
	}

	status.HealthStatus.Updated = uint32(time.Now().Unix())

	c.RenderString("OK")
}

func (c Health) StatusAction() {
	c.RenderJson(status.HealthStatus)
}
