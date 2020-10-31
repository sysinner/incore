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

package config

import (
	"github.com/sysinner/injob/v1"
)

type ConfigJob struct {
	spec     *injob.JobSpec
	mainNode bool
}

func (it *ConfigJob) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("incore/config")
	}
	return it.spec
}

func (it *ConfigJob) Status() *injob.Status {
	return nil
}

func (it *ConfigJob) Run(ctx *injob.Context) error {

	if len(Config.Zone.MainNodes) == 0 {
		return nil
	}

	if IsZoneMaster() {
		if !it.mainNode {
			it.mainNode = true
			ctx.ConditionSet("zone/main-node", -1)
		}
	} else {
		it.mainNode = false
		ctx.ConditionDel("zone/main-node")
	}

	return nil
}

func NewConfigJob() *injob.JobEntry {
	return injob.NewJobEntry(&ConfigJob{},
		injob.NewSchedule().EveryTimeCycle(injob.Second, 3))
}
