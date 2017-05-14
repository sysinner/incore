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

package losapi

type OpPerm uint8

const (
	OpRead   OpPerm = 1 << 0
	OpWrite  OpPerm = 1 << 1
	OpCreate OpPerm = 1 << 2
	OpDelete OpPerm = 1 << 3
	OpList   OpPerm = 1 << 4
	OpPut    OpPerm = OpWrite | OpCreate
	OpMirror OpPerm = OpRead | OpList
	OpAll    OpPerm = OpRead | OpWrite | OpCreate | OpDelete | OpList
)

func (p OpPerm) Allow(perms OpPerm) bool {
	return (perms & p) == perms
}
