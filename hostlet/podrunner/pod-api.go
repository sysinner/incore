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

package podrunner

import (
	"errors"
	"fmt"

	"github.com/lessos/lessgo/logger"

	"code.hooto.com/lessos/loscore/losapi"
)

func PodEntry(pod_id string) losapi.Pod {

	pod_mu.Lock()
	defer pod_mu.Unlock()

	if entry, ok := pod_instances[pod_id]; ok {
		return *entry
	}

	return losapi.Pod{}
}

func PodStatus(pod_id string) losapi.PodStatus {

	pod_mu.Lock()
	defer pod_mu.Unlock()

	if v, ok := pod_instances[pod_id]; ok {

		if v.Status != nil {
			return *v.Status
		}
	}

	return losapi.PodStatus{}
}

func LocalAppSync(app losapi.AppInstance) error {

	pod_mu.Lock()
	defer pod_mu.Unlock()

	if app.Spec.Vendor != "local" {
		return errors.New("Invalid Vendor Value")
	}

	pod, ok := pod_instances[app.Operate.PodId]
	if !ok {
		return fmt.Errorf("No Pod Found")
	}

	logger.Printf("info", "nodelet/data_agent ctrlAppUpdate %s/%s", app.Operate.PodId, app.Meta.Name)

	pod.Apps.Sync(app)

	box_keeper.ctr_sync(pod)

	return nil
}
