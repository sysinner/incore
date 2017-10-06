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

type OpPerm uint8

const (
	OpPermRead   OpPerm = 1 << 0
	OpPermWrite  OpPerm = 1 << 1
	OpPermCreate OpPerm = 1 << 2
	OpPermDelete OpPerm = 1 << 3
	OpPermList   OpPerm = 1 << 4
	OpPermPut    OpPerm = OpPermWrite | OpPermCreate
	OpPermMirror OpPerm = OpPermRead | OpPermList
	OpPermAll    OpPerm = OpPermRead | OpPermWrite | OpPermCreate | OpPermDelete | OpPermList
)

func (p OpPerm) Allow(perms OpPerm) bool {
	return (perms & p) == perms
}