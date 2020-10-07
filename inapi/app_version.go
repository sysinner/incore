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
	"strconv"
	"strings"

	"github.com/sysinner/incore/inutils"
)

const (
	vmax int64 = 99999999
)

type AppSpecVersion struct {
	str   string
	num   int
	Major uint32
	Minor uint32
	Patch uint32
}

func NewAppSpecVersion(vstr string) *AppSpecVersion {
	v := &AppSpecVersion{
		str: vstr,
	}
	return v.parsefix()
}

func (v *AppSpecVersion) Valid() bool {

	if v.str == "" {
		return false
	}

	v.parsefix()
	if v.Major < 1 && v.Minor < 1 && v.Patch < 1 {
		return false
	}

	return true
}

// Compare compares this version to another version. This
// returns -1, 0, or 1 if this version is smaller, equal,
// or larger than the compared version, respectively.
func (va *AppSpecVersion) Compare(vb *AppSpecVersion) int {

	vsa, vsb := va.parsefix(), vb.parsefix()

	// 0  va == vb
	// -1 va < vb
	// +1 va > vb.
	ha, hb := vsa.IndexId(), vsb.IndexId()
	if ha == hb {
		return 0
	} else if ha < hb {
		return -1
	}
	return 1
}

func (v *AppSpecVersion) Add(Major, Minor, Patch bool) *AppSpecVersion {

	v.parsefix()

	if Major {
		v.Major += 1
		v.Minor = 0
		v.Patch = 0
	} else if Minor {
		v.Minor += 1
		v.Patch = 0
	} else if Patch {
		v.Patch += 1
	}

	return v
}

func (v *AppSpecVersion) IndexId() int64 {
	v.parsefix()
	return (int64(v.Major) * vmax * vmax) +
		(int64(v.Minor) * vmax) +
		int64(v.Patch)
}

func (v *AppSpecVersion) FullVersion() string {
	v.parsefix()
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v *AppSpecVersion) MajorMinorVersion() string {
	v.parsefix()
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

func (v *AppSpecVersion) PrefixString() string {
	v.parsefix()
	if v.num == 3 {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

func (v *AppSpecVersion) FullHexString() string {
	v.parsefix()
	return fmt.Sprintf("%s.%s.%s",
		inutils.Uint32ToHexString(v.Major),
		inutils.Uint32ToHexString(v.Minor),
		inutils.Uint32ToHexString(v.Patch))
}

func (v *AppSpecVersion) HexString() string {
	v.parsefix()
	if v.num == 3 {
		return fmt.Sprintf("%s.%s.%s",
			inutils.Uint32ToHexString(v.Major),
			inutils.Uint32ToHexString(v.Minor),
			inutils.Uint32ToHexString(v.Patch))
	}
	return fmt.Sprintf("%s.%s",
		inutils.Uint32ToHexString(v.Major),
		inutils.Uint32ToHexString(v.Minor))
}

func (v *AppSpecVersion) parsefix() *AppSpecVersion {

	if v.Major < 1 && v.Minor < 1 && v.Patch < 1 {

		if v.str != "" {

			vs := strings.Split(v.str, ".")
			if len(vs) == 1 {
				iv, _ := strconv.Atoi(vs[0])
				v.Patch = uint32(iv)
				v.num = 3
			} else if len(vs) >= 2 {
				v.num = len(vs)
				if v.num > 3 {
					v.num = 3
				}
				for i, is := range vs {
					iv, _ := strconv.Atoi(is)
					if i == 0 {
						v.Major = uint32(iv)
					} else if i == 1 {
						v.Minor = uint32(iv)
					} else {
						v.Patch = uint32(iv)
						break
					}
				}
			}
		}

	} else {
		if v.Patch > uint32(vmax) {
			v.Patch = 0
			v.Minor += 1
		}
		if v.Minor > uint32(vmax) {
			v.Minor = 0
			v.Major += 1
		}
		if v.Major > uint32(vmax) {
			v.Major = uint32(vmax)
		}
	}

	return v
}
