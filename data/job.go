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

package data

import (
	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/injob/v1"
)

type DataJob struct {
	spec       *injob.JobSpec
	zoneInited bool
}

func (it *DataJob) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("incore/data")
	}
	return it.spec
}

func (it *DataJob) Status() *injob.Status {
	return nil
}

func (it *DataJob) Run(ctx *injob.Context) error {

	if !incfg.IsZoneMaster() {
		return nil
	}

	if !it.zoneInited {
		err := setupZone()
		if err == nil {
			it.zoneInited = true
		}
		return err
	}

	return nil
}

func NewDataJob() *injob.JobEntry {
	return injob.NewJobEntry(&DataJob{},
		injob.NewSchedule().EveryTimeCycle(injob.Second, 3))
}
