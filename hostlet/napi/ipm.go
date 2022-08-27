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

package napi

import (
	"fmt"
	"runtime"
)

func InPackMountPath(name, version string) string {
	return fmt.Sprintf("/usr/sysinner/%s/%s", name, version)
}

func InPackHostDir(name, version, release, dist, arch string) string {
	p := fmt.Sprintf("/opt/sysinner/ipm/%s/%s/%s.%s.%s", name, version, release, dist, arch)
	if runtime.GOOS == "darwin" {
		return "/Volumes" + p
	}
	return p
}
