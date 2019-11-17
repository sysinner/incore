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
	"github.com/lynkdb/iomix/sko"

	"github.com/sysinner/incore/data"
)

func InitData(items []*sko.ClientObjectItem) error {

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

		hlog.Printf("info", "init.data key %s", string(v.Key))
		continue

		if rs := data.DataZone.NewWriter(v.Key, v.Value).
			ModeCreateSet(true).Commit(); !rs.OK() {
			return fmt.Errorf("zm.initdata error on key : %s", string(v.Key))
		}

		/**
		if len(k) > 5 && (k[:4] == "ing:" || k[:4] == "inz:") {

			if _, ok := hflag.ValueOK("zm-init-data-force-rewrite"); ok {
				if rs := data.DataGlobal.NewWriter([]byte(k), v).Commit(); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}

			} else {
				if rs := data.DataGlobal.NewReader([]byte(k)).Query(); rs.OK() {
					hlog.Printf("debug", "gm.init.data skip %s", k)
					continue
				}

				if rs := data.DataGlobal.NewWriter([]byte(k), v).
					ModeCreateSet(true).Commit(); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}
			}

		} else if len(k) > 5 && (k[:5] == "/ing/" || k[:5] == "/iam/") {

			if _, ok := hflag.ValueOK("zm-init-data-force-rewrite"); ok {
				if rs := data.DataGlobal.NewWriter(k, v).Commit(); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}

			} else {
				if rs := data.DataGlobal.NewReader(k); rs.OK() {
					hlog.Printf("debug", "gm.init.data skip %s", k)
					continue
				}

				if rs := data.DataGlobal.NewWriter(k, v).
					ModeCreateSet(true).Commit(); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}
			}

		} else {

			if _, ok := hflag.ValueOK("zm-init-data-force-rewrite"); ok {
				if rs := data.DataGlobal.NewWriter(k, v).Commit(); !rs.OK() {
					return fmt.Errorf("gm.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "gm.init.data set %s", k)
				}

			} else {
				if rs := data.DataZone.NewReader(k); rs.OK() {
					hlog.Printf("debug", "zm.init.data skip %s", k)
					continue
				}

				if rs := data.DataZone.NewWriter(k, v).
					ModeCreateSet(true).Commit(); !rs.OK() {
					return fmt.Errorf("zonemaster.initdata error on put key : %s", k)
				} else {
					hlog.Printf("info", "zm.init.data set %s", k)
				}
			}
		}
		*/
	}

	return nil
}
