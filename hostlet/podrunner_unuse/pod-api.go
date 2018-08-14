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
	"errors"
	"fmt"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/inapi"
)

func PodEntry(pod_id string) inapi.Pod {

	entry := PodRepActives.Get(inapi.NsZonePodOpRepKey(pod_id, 0))
	if entry != nil {
		return *entry
	}

	return inapi.Pod{}
}

func PodStatus(pod_id string) inapi.PodStatus {

	entry := PodRepActives.Get(inapi.NsZonePodOpRepKey(pod_id, 0))
	if entry != nil && entry.Status != nil {
		return *entry.Status
	}

	return inapi.PodStatus{}
}

func LocalAppSync(app inapi.AppInstance) error {

	if app.Spec.Vendor != "local" {
		return errors.New("Invalid Vendor Value")
	}

	pod := PodRepActives.Get(inapi.NsZonePodOpRepKey(app.Operate.PodId, 0))
	if pod == nil {
		return fmt.Errorf("No Pod Found")
	}

	hlog.Printf("info", "hostlet/data_agent ctrlAppUpdate %s/%s",
		app.Operate.PodId, app.Meta.Name)

	pod.Apps.Sync(app)

	return nil
}
