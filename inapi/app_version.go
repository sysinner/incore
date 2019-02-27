// Copyright 2018 Eryx <evorui аt gmail dοt com>, All rights reserved.
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
	"fmt"
)

var (
	asv_major_size int32 = 1 << 8
	asv_minor_size int32 = 1 << 24
)

type AppSpecVersion struct {
	str   string
	major int32
	minor int32
}

func NewAppSpecVersion(vstr string) *AppSpecVersion {
	return &AppSpecVersion{
		str: vstr,
	}
}

func (v *AppSpecVersion) Valid() bool {

	if v.str == "" {
		return false
	}

	v.parse_fix()
	if v.major < 1 && v.minor < 1 {
		return false
	}

	return true
}

// Compare compares this version to another version. This
// returns -1, 0, or 1 if this version is smaller, equal,
// or larger than the compared version, respectively.
func (v *AppSpecVersion) Compare(other *AppSpecVersion) int {

	vs, vs2 := v.parse_fix(), other.parse_fix()
	if lg := (vs.major*asv_minor_size + vs.minor) - (vs2.major*asv_minor_size + vs2.minor); lg > 0 {
		return 1
	} else if lg < 0 {
		return -1
	}

	return 0
}

func (v *AppSpecVersion) Add(major, minor bool) *AppSpecVersion {

	v.parse_fix()

	if minor {
		v.minor += 1
	} else if major {
		v.major += 1
		v.minor = 0
	}

	return v
}

func (v *AppSpecVersion) String() string {
	v.parse_fix()
	return fmt.Sprintf("%d.%d", v.major, v.minor)
}

func (v *AppSpecVersion) Uint32() uint32 {
	v.parse_fix()
	return uint32((v.major * asv_minor_size) + v.minor)
}

func (v *AppSpecVersion) parse_fix() *AppSpecVersion {

	if v.major < 1 && v.minor < 1 {

		for _, char := range v.str {
			if char >= '0' && char <= '9' {
				if v.minor > 0 {
					v.minor = 10 * v.minor
				}
				v.minor += (char - '0')
			} else if v.minor > 0 {
				v.major = v.minor
				v.minor = 0
			}
		}
	}

	if v.minor >= asv_minor_size {
		v.major += 1
		v.minor = 0
	}

	if v.major >= asv_major_size {
		v.major = asv_major_size - 1
	}

	return v
}
