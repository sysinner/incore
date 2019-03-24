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

	"github.com/hooto/hflag4g/hflag"
	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/incore/data"
)

func InitData(items map[string]interface{}) error {

	if data.GlobalMaster == nil {
		return fmt.Errorf("data.GlobalMaster Not Init")
	}

	if data.ZoneMaster == nil {
		return fmt.Errorf("data.ZoneMaster Not Init")
	}

	for k, v := range items {

		if len(k) > 5 && (k[:5] == "/ing/" || k[:5] == "/iam/") {

			if _, ok := hflag.ValueOK("zm-init-data-force-rewrite"); ok {
				if rs := data.GlobalMaster.PvPut(k, v, nil); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}

			} else {
				if rs := data.GlobalMaster.PvGet(k); rs.OK() {
					hlog.Printf("debug", "gm.init.data skip %s", k)
					continue
				}

				if rs := data.GlobalMaster.PvNew(k, v, nil); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}
			}

		} else {

			if _, ok := hflag.ValueOK("zm-init-data-force-rewrite"); ok {
				if rs := data.GlobalMaster.PvPut(k, v, nil); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}

			} else {
				if rs := data.ZoneMaster.PvGet(k); rs.OK() {
					hlog.Printf("debug", "zm.init.data skip %s", k)
					continue
				}

				if rs := data.ZoneMaster.PvNew(k, v, nil); !rs.OK() {
					return fmt.Errorf("zonemaster.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "zm.init.data set %s", k)
				}
			}
		}
	}

	return nil
}
