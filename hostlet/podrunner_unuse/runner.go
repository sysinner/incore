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

package podrunner

import (
	"github.com/sysinner/incore/inapi"
)

var (
	PodRepActives  inapi.PodSets
	PodRepOpLogs   inapi.OpLogList
	BoxActives     BoxInstanceSets
	pod_op_pulling = false
	PodQueue       inapi.PodSets // TODO
)

func Run() error {

	go func() {

		if pod_op_pulling {
			return
		}

		pod_op_pulling = true
		pod_op_pull()
		pod_op_pulling = false
	}()

	return nil
}
