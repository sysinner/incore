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

package hostlet

import (
	"fmt"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/hostlet/nstatus"
)

func Setup() error {
	//
	json.DecodeFile(config.Prefix+"/etc/hostlet-actives.json", &nstatus.BoxActives)
	for _, v := range nstatus.BoxActives.Items {
		v.Status.Action = 0
	}

	hlog.Printf("info", "hostlet setup, replicas %d", len(nstatus.BoxActives.Items))
	return nil
}

func ConfigFlush() error {
	return json.EncodeToFile(nstatus.BoxActives, config.Prefix+"/etc/hostlet-actives.json", "  ")
}

func InitData(items map[string]interface{}) error {

	if data.DataLocal == nil {
		return fmt.Errorf("data.DataLocal Not Init")
	}

	for k, v := range items {

		if rs := data.DataLocal.NewWriter([]byte(k), v).Commit(); !rs.OK() {
			return fmt.Errorf("hostlet.initdata error on put key : %s", k)
		}

		hlog.Printf("info", "hostlet.init.data set %s", k)
	}

	return nil
}
