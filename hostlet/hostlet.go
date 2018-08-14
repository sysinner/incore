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
	"fmt"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"

	"github.com/sysinner/incore/hostlet/box/docker"
	"github.com/sysinner/incore/hostlet/box/pouch"
)

var (
	mu         sync.Mutex
	running    = false
	boxDrivers []napi.BoxDriver
)

func Start() error {

	mu.Lock()
	defer mu.Unlock()

	if running {
		return nil
	}
	running = true

	if dr, err := docker.NewDriver(); err == nil {
		boxDrivers = append(boxDrivers, dr)
	}

	if dr, err := pouch.NewDriver(); err == nil {
		boxDrivers = append(boxDrivers, dr)
	}

	for _, dv := range boxDrivers {
		if err := dv.Start(); err != nil {
			hlog.Printf("error", "box.Driver %s Start Error %s", dv.Name(), err.Error())
		}
	}

	go func() {

		for {

			status_tracker()

			podOpPull()

			actions := boxActionRefresh()

			for _, dv := range boxDrivers {
				for {
					sts := dv.StatusEntry()
					if sts == nil {
						break
					}
					boxStatusSync(sts)
				}
				for {
					sts := dv.StatsEntry()
					if sts == nil {
						break
					}
					boxStatsSync(sts)
				}
			}

			for _, action_inst := range actions {

				for _, dv := range boxDrivers {

					if dv.Name() != action_inst.Spec.Image.Driver {
						continue
					}

					go func(dv napi.BoxDriver, inst *napi.BoxInstance) {

						// napi.ObjPrint("action command", inst)

						if err := dv.ActionCommandEntry(inst); err != nil {
							nstatus.PodRepOpLogs.LogSet(
								inst.OpRepKey(), inst.PodOpVersion,
								napi.OpLogNsCtnCmd, inapi.PbOpLogError, fmt.Sprintf("box/%s ERR:%s", inst.Name, err.Error()),
							)
						} else {
							nstatus.PodRepOpLogs.LogSet(
								inst.OpRepKey(), inst.PodOpVersion,
								napi.OpLogNsCtnCmd, inapi.PbOpLogOK, fmt.Sprintf("box/%s OK", inst.Name),
							)
						}
					}(dv, action_inst)
				}
			}

			time.Sleep(3e9)
		}
	}()

	hlog.Printf("info", "hostlet started")

	return nil
}
