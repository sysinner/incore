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
	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/injob"
	// "github.com/sysinner/incore/inapi"
	// "github.com/sysinner/incore/inrpc"
)

type HostletJob struct {
	spec *injob.JobSpec
	rpc  bool
}

func (it *HostletJob) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("incore/hostlet")
	}
	return it.spec
}

func (it *HostletJob) Status() *injob.Status {
	return nil
}

func (it *HostletJob) Run(ctx *injob.Context) error {

	if len(incfg.Config.Zone.MainNodes) == 0 {
		return nil
	}

	if !running {
		if err := Start(); err != nil {
			return err
		}
	}

	/**
	if !it.rpc {
		if err := inrpc.RegisterServer(func(s *inrpc.Server) {
			inapi.RegisterApiHostMemberServer(s, new(ApiHostMember))
		}); err != nil {
			return err
		}
		it.rpc = true
	}
	*/

	return nil
}

func NewHostletJob() *injob.JobEntry {
	return injob.NewJobEntry(&HostletJob{},
		injob.NewSchedule().EveryTimeCycle(injob.Second, 3))
}
