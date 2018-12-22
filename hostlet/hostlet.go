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
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/hostlet/napi"

	"github.com/sysinner/incore/hostlet/box/docker"
	"github.com/sysinner/incore/hostlet/box/pouch"
)

var (
	mu         sync.Mutex
	running    = false
	boxDrivers napi.BoxDriverList
)

func Start() error {

	mu.Lock()
	defer mu.Unlock()

	if running {
		return nil
	}
	running = true

	if dr, err := docker.NewDriver(); err == nil {
		boxDrivers.Items = append(boxDrivers.Items, dr)
	}

	if dr, err := pouch.NewDriver(); err == nil {
		boxDrivers.Items = append(boxDrivers.Items, dr)
	}

	for _, dv := range boxDrivers.Items {
		if err := dv.Start(); err != nil {
			hlog.Printf("error", "box.Driver %s Start Error %s", dv.Name(), err.Error())
		}
	}

	go func() {

		for {
			time.Sleep(3e9)

			for _, dv := range boxDrivers.Items {
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

			if err := zoneMasterSync(); err != nil {
				hlog.Printf("warn", "hostlet/zm/sync %s", err.Error())
				continue
			}

			podRepListCtrlRefresh()
		}
	}()

	hlog.Printf("info", "hostlet started")

	return nil
}
