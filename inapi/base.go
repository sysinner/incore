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

package inapi

import (
	"encoding/json"
	"time"

	"github.com/spf13/cobra"
)

type BaseCommand = cobra.Command

type jsonObjectMeta ObjectMeta

func (it *ObjectMeta) UnmarshalJSON(b []byte) error {

	var it2 jsonObjectMeta
	if err := json.Unmarshal(b, &it2); err != nil {
		return err
	}

	it2.Created = timeUpgrade(it2.Created)
	it2.Updated = timeUpgrade(it2.Updated)

	*it = ObjectMeta(it2)

	return nil
}

func timeUpgrade(tn uint64) uint64 {
	if tn < 20000101000000111 {
		return tn
	}
	mtu := uint64(tn)
	return uint64(time.Date(int(mtu/1e13), time.Month((mtu%1e13)/1e11), int((mtu%1e11)/1e9),
		int((mtu%1e9)/1e7), int((mtu%1e7)/1e5), int((mtu%1e5)/1e3),
		int(mtu%1e3)*1e6, time.UTC).UnixNano() / 1e6)
}
