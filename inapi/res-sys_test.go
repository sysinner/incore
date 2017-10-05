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

package inapi

import (
	"testing"
)

func TestResHostListSync(t *testing.T) {

	dst := &ResHost{}

	dst.Sync(ResHost{
		Meta: &ObjectMeta{
			Id: "demo",
		},
	})

	if dst.Meta == nil {
		t.Fatal("Failed diff dst.Meta.Id")
	}

	if dst.Meta.Id != "demo" {
		t.Fatal("Failed diff dst.Meta.Id")
	}

	dst.Sync(ResHost{
		Meta: &ObjectMeta{
		// Id: "",
		},
	})

	if dst.Meta.Id != "demo" {
		t.Fatal("Failed diff dst.Meta.Id")
	}
}
