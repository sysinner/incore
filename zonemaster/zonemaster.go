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

package zonemaster

import (
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	iamWorker "github.com/hooto/iam/worker"

	"github.com/sysinner/incore/status"
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

	hlog.Print("info", "zonemaster/worker started")

	go func() {

		for {

			time.Sleep(3e9)

			zoneTracker()

			if status.IsZoneMasterLeader() {
				if err := schedAction(); err != nil {
					hlog.Printf("warn", "zm/scheduler err:%s", err.Error())
				}
				if err := podChargeRefresh(); err != nil {
					hlog.Printf("warn", "zm/pod/charge err:%s", err.Error())
				}

				go iamWorker.AccountChargeCloseRefresh()
			}
		}
	}()

	return nil
}
