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
	"os/exec"

	incfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/box/docker"
	"github.com/sysinner/injob/v1"
)

func JobSetup(jobDaemon *injob.Daemon) {
	jobDaemon.Commit(NewHostletJob())
	jobDaemon.Commit(docker.NewBoxImageUpdateJob())
}

type HostletJob struct {
	spec   *injob.JobSpec
	rpc    bool
	inited bool
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

	// TODO
	if !it.inited {

		script := `sed -i 's/SELINUX\=enforcing/SELINUX\=disabled/g' /etc/selinux/config
setenforce 0
`
		if _, err := exec.Command("bash", "-c", script).Output(); err != nil {
			// skip error
		}

		for _, v := range []string{
			"firewalld",
		} {
			if _, err := exec.Command("systemctl", "disable", v).Output(); err != nil {
				// return err
			}

			if _, err := exec.Command("systemctl", "stop", v).Output(); err != nil {
				// return err
			}
		}

		for _, v := range []string{
			"innerstack-lxcfs",
		} {
			if _, err := exec.Command("systemctl", "enable", v).Output(); err != nil {
				return err
			}

			if _, err := exec.Command("systemctl", "start", v).Output(); err != nil {
				return err
			}
		}

		it.inited = true
	}

	if running {
		return nil
	}

	if err := Start(); err != nil {
		return err
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
