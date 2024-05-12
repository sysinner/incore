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

	"github.com/sysinner/incore/data"
)

func InitData(items map[string]interface{}) error {

	if data.DataGlobal == nil {
		return fmt.Errorf("data.DataGlobal Not Init")
	}

	if data.DataZone == nil {
		return fmt.Errorf("data.DataZone Not Init")
	}

	if len(items) == 0 {
		return nil
	}

	for key, value := range items {

		if strings.HasPrefix(key, "ing:") ||
			strings.Contains(key, "/ing/") {

			if rs := data.DataGlobal.NewWriter([]byte(key), value).
				SetCreateOnly(true).Exec(); !rs.OK() {
				return fmt.Errorf("gm.initdata error on key : %s", key)
			} else if rs.Item().Meta.Updated > 0 {
				continue
			}
		}

		if strings.HasPrefix(key, "inz:") ||
			strings.Contains(key, "/inz/") {

			if rs := data.DataZone.NewWriter([]byte(key), value).
				SetCreateOnly(true).Exec(); !rs.OK() {
				return fmt.Errorf("zm.initdata error on key : %s", key)
			} else if rs.Item().Meta.Updated > 0 {
				continue
			}
		}

		hlog.Printf("info", "init.data skip key %s", key)
	}

	return nil
}
