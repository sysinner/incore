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

package data

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lynkdb/iomix/sko"
	"github.com/lynkdb/iomix/skv"

	"github.com/sysinner/incore/inapi"
)

func upgrade_v091(dbPrevDriver string,
	dbPrev skv.Connector, dbNext sko.ClientConnector) error {

	if dbPrev == nil || dbNext == nil {
		return errors.New("invalid connect")
	}

	var (
		limit  = 1000
		numAll = 0
		tStart = time.Now()
	)

	// Kv*
	if true {

		var (
			offset = []byte("00")
			cutset = []byte("zz")
			num    = 0
		)

		for {

			rs := dbPrev.KvScan(offset, cutset, limit)
			if !rs.OK() {
				return errors.New("server error")
			}

			rss := rs.KvList()
			for _, obj := range rss {

				offset = obj.Key
				key := string(obj.Key)

				if !strings.HasPrefix(key, "ing:") &&
					!strings.HasPrefix(key, "inz:") {
					if !strings.HasPrefix(key, "iam:") {
						hlog.Printf("warn", "Upgrade SKIP %s", key)
					}
					continue
				}

				if strings.HasPrefix(key, "inz:sys:host:stats:") ||
					strings.HasPrefix(key, "inz:pod:stats:") {
					continue
				}

				if strings.HasPrefix(key, "ing:z:") {
					// hlog.Printf("warn", "Upgrade SKIP %s", key)
					// continue
				}

				if len(obj.Value) < 2 {
					hlog.Printf("warn", "Upgrade SKIP %s", key)
					continue
				}

				if obj.Value[0] == 0 {

					if rs := dbNext.NewWriter([]byte(key), string(obj.Value[1:])).
						ModeCreateSet(true).Commit(); !rs.OK() {
						return fmt.Errorf("db err %s", rs.Message)
					} else if rs.Meta.Created > 0 && rs.Meta.Updated == 0 {
						//
					} else {
					}

					num += 1

					hlog.Printf("warn", "Upgrade %s, Value %s", key, string(obj.Value[1:]))

				} else if obj.Value[0] == 20 { // JSON

					if rs := dbNext.NewWriter([]byte(key), string(obj.Value[1:])).
						ModeCreateSet(true).Commit(); !rs.OK() {
						return fmt.Errorf("db err %s", rs.Message)
					} else if rs.Meta.Created > 0 && rs.Meta.Updated == 0 {
						// already created
					} else {

						num += 1
						hlog.Printf("warn", "Upgrade %s", key)
					}

				} else {
					hlog.Printf("warn", "Upgrade SKIP %s", key)
				}
			}

			if len(rss) < limit {
				break
			}
		}

		if num > 0 {
			hlog.Printf("warn", "Upgrade KV %d", num)
		}
		numAll += num
	}

	// Raw
	if true {

		var (
			offset = []byte{}
			cutset = []byte{}
			num    = 0
		)

		if dbPrevDriver == "lynkstorgo" {
			offset = []byte{0, 0}
			cutset = []byte{255, 255}
		} else {
			offset = []byte{36}
			cutset = []byte{36}
		}

		for {

			rs := dbPrev.RawScan(offset, cutset, limit)
			if !rs.OK() {
				return errors.New("server error")
			}

			rss := rs.KvList()
			// hlog.Printf("info", "Keys %d", len(rss))
			for _, obj := range rss {

				offset = obj.Key

				pk := skv.KvProgKeyDecode(obj.Key)
				if len(pk.Items) < 2 {
					continue
				}

				if string(pk.Items[0].Data) == "iam" {
					continue
				}

				if string(pk.Items[0].Data) == "ing" &&
					string(pk.Items[1].Data) == "asv" {
					continue
				}

				if len(pk.Items[len(pk.Items)-1].Data) == 0 {
					continue
				}

				key := inapi.NsKeyPathFilter("/" + strings.Join(pk.DumpArrayString(), "/"))

				// hlog.Printf("info", "Key %s", string(key))
				if strings.Contains(string(key), "hostkey") {
					// hlog.Printf("info", "Key %s, Value %s", string(key), string(obj.Value[1:]))
				}

				if string(pk.Items[0].Data) != "ing" &&
					string(pk.Items[0].Data) != "inz" {
					if string(pk.Items[0].Data) != "iam" {
						hlog.Printf("warn", "Upgrade SKIP %s", key)
					}
					continue
				}

				if len(obj.Value) < 2 {
					continue
				}

				if obj.Value[0] == 32 {

					meta_len := int(obj.Value[1])
					if len(obj.Value) <= (meta_len + 2) {
						hlog.Printf("warn", "Upgrade SKIP %s", key)
						continue
					}

					obj.Value = obj.Value[(meta_len + 2):]
				}

				if len(obj.Value) < 2 {
					hlog.Printf("warn", "Upgrade SKIP %s", key)
					continue
				}

				if obj.Value[0] == 0 {

					if rs := dbNext.NewWriter([]byte(key), string(obj.Value[1:])).
						ModeCreateSet(true).Commit(); !rs.OK() {
						return fmt.Errorf("db err %s", rs.Message)
					} else if rs.Meta.Created > 0 && rs.Meta.Updated == 0 {
						//
					} else {
						num += 1
						hlog.Printf("warn", "Upgrade %s, Value %s", key, string(obj.Value[1:]))
					}

				} else if obj.Value[0] == 20 { // JSON

					if rs := dbNext.NewWriter([]byte(key), string(obj.Value[1:])).
						ModeCreateSet(true).Commit(); !rs.OK() {
						return fmt.Errorf("db err %s", rs.Message)
					} else if rs.Meta.Created > 0 && rs.Meta.Updated == 0 {
						//
					} else {
						num += 1
						hlog.Printf("warn", "Upgrade %s", key)
					}

				} else {
					hlog.Printf("warn", "Upgrade SKIP %s, Value Type %d", key, obj.Value[0])
				}
			}

			if len(rss) < limit {
				break
			}
		}

		if num > 0 {
			hlog.Printf("warn", "Upgrade RAW %d", num)
		}
		numAll += num
	}

	if numAll > 0 {
		hlog.Printf("warn", "Upgrade %d items, in %v", numAll, time.Since(tStart))
	}

	return nil
}
