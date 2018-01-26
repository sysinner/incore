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
	"github.com/sysinner/incore/hostlet/podrunner"
)

var (
	mu      sync.Mutex
	running = false
)

func Start() error {

	mu.Lock()
	defer mu.Unlock()

	if running {
		return nil
	}

	hlog.Printf("info", "hostlet started")

	podrunner.BoxDrivers = append(podrunner.BoxDrivers, &podrunner.BoxDriverRkt{})

	for _, dv := range podrunner.BoxDrivers {
		go dv.Run()
	}

	go func() {

		for {

			status_tracker()

			if err := podrunner.Run(); err != nil {
				hlog.Printf("error", "podrunner.Run %s", err.Error())
			}

			time.Sleep(3e9)
		}
	}()

	return nil
}
