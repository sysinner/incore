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
	"sync"
	"time"
)

var (
	DaemonDefault = &Daemon{}
)

type Daemon struct {
	mu      sync.Mutex
	jobs    []*JobEntry
	ctx     *Context
	running bool
	cr      ContextRefresher
}

func NewDaemon(cr ContextRefresher) (*Daemon, error) {
	return &Daemon{
		cr: cr,
	}, nil
}

func (it *Daemon) Commit(j *JobEntry) *JobEntry {

	it.mu.Lock()
	defer it.mu.Unlock()

	for _, v := range it.jobs {
		if v.job.Name() == j.job.Name() {
			v.status = StatusOK
			if j.sch != nil {
				v.sch = j.sch
			}
			return v.Commit()
		}
	}

	it.jobs = append(it.jobs, j)

	return j.Commit()
}

func (it *Daemon) Start() {

	it.mu.Lock()
	if it.running {
		it.mu.Unlock()
		return
	}
	it.running = true
	it.mu.Unlock()

	tr := time.NewTicker(time.Second)
	defer tr.Stop()

	ctx := &Context{}

	for {

		tn := <-tr.C
		st := scheduleTime(tn)

		if it.cr != nil {
			ctx = it.cr()
		}

		for _, j := range it.jobs {

			if !j.Schedule().Hit(st) {
				continue
			}

			go j.exec(ctx)
		}
	}
}
