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

type Daemon struct {
	mu         sync.Mutex
	cmu        sync.RWMutex
	jobs       []*JobEntry
	ctx        *Context
	running    bool
	cr         ContextRefresher
	conditions map[string]int64
}

func NewDaemon(cr ContextRefresher) (*Daemon, error) {
	return &Daemon{
		cr:         cr,
		conditions: map[string]int64{},
	}, nil
}

func (it *Daemon) Commit(j *JobEntry) *JobEntry {

	it.mu.Lock()
	defer it.mu.Unlock()

	for _, v := range it.jobs {
		if v.job.Spec().Name == j.job.Spec().Name {
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

func (it *Daemon) conditionAllow(j *JobEntry) bool {

	if len(j.job.Spec().Conditions) == 0 {
		return true
	}

	it.cmu.RLock()
	defer it.cmu.RUnlock()

	tn := time.Now().UnixNano() / 1e6

	for c, v := range j.job.Spec().Conditions {

		t, ok := it.conditions[c]
		if !ok {
			return false
		}

		if v == -1 || t+v >= tn {
			return true
		}

		break
	}

	return false
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

		if ctx.daemon == nil {
			ctx.daemon = it
		}

		for _, j := range it.jobs {

			if !it.conditionAllow(j) {
				continue
			}

			if !j.Schedule().Hit(st) {
				continue
			}

			go j.exec(ctx)
		}
	}
}

func (it *Daemon) conditionSet(name string, v int64) {
	it.cmu.Lock()
	defer it.cmu.Unlock()
	it.conditions[name] = v
}

func (it *Daemon) conditionDel(name string) {
	it.cmu.Lock()
	defer it.cmu.Unlock()
	delete(it.conditions, name)
}
