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

package injob

import (
	"github.com/sysinner/incore/inapi"
)

type ContextRefresher func() *Context

type Context struct {
	Zone              *inapi.ResZone
	ZoneHostList      *inapi.ResHostList
	ZonePodList       *inapi.PodList
	ZonePodStatusList *inapi.PodStatusList
	IsZoneLeader      bool
}
