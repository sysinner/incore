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

package job

import (
	"fmt"
	"time"
)

func scheduleFields(min, max uint) uint64 {
	fv := uint64(0)
	for i := min; i <= max; i++ {
		fv = fv | (1 << i)
	}
	return fv
}

func u64Allow(opbase, op uint64) bool {
	return (op & opbase) == op
}

type DemoJob struct{}

func (it *DemoJob) Name() string {
	return "demo-job"
}

func (it *DemoJob) Run(ctx *Context) error {
	time.Sleep(4e9)
	fmt.Println("demojob run at", time.Now().Unix())
	return nil
}
