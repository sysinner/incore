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
	"fmt"
	"strings"

	"github.com/hooto/hlog4g/hlog"
	kv2 "github.com/lynkdb/kvspec/v2/go/kvspec"

	"github.com/sysinner/incore/data"
)

func InitData(items []*kv2.ClientObjectItem) error {

	if data.DataGlobal == nil {
		return fmt.Errorf("data.DataGlobal Not Init")
	}

	if data.DataZone == nil {
		return fmt.Errorf("data.DataZone Not Init")
	}

	for _, v := range items {

		if strings.HasPrefix(string(v.Key), "ing:") ||
			strings.Contains(string(v.Key), "/ing/") {

			if rs := data.DataGlobal.NewWriter(v.Key, v.Value).
				ModeCreateSet(true).Commit(); !rs.OK() {
				return fmt.Errorf("gm.initdata error on key : %s", string(v.Key))
			} else if rs.Meta.Created > 0 {
				continue
			}
		}

		if strings.HasPrefix(string(v.Key), "inz:") ||
			strings.Contains(string(v.Key), "/inz/") {

			if rs := data.DataZone.NewWriter(v.Key, v.Value).
				ModeCreateSet(true).Commit(); !rs.OK() {
				return fmt.Errorf("zm.initdata error on key : %s", string(v.Key))
			} else if rs.Meta.Created > 0 {
				continue
			}
		}

		hlog.Printf("info", "init.data skip key %s", string(v.Key))
	}

	return nil
}
