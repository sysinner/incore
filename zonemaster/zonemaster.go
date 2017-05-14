// Copyright 2015 Authors, All rights reserved.
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

package zonemaster

import (
	"sync"
	"time"

	"github.com/lessos/lessgo/logger"

	"code.hooto.com/lessos/loscore/status"
)

var (
	worker_mu sync.Mutex
	running   = false
)

func Start() error {

	worker_mu.Lock()
	defer worker_mu.Unlock()

	if running {
		return nil
	}

	logger.Print("info", "zonemaster/worker started")

	go func() {

		for {

			time.Sleep(3e9)

			zone_tracker()

			if status.IsZoneMasterLeader() {
				if err := scheduler_exec(); err != nil {
					logger.Printf("warn", "zm/scheduler err:%s", err.Error())
				}
			}
		}
	}()

	return nil
}
