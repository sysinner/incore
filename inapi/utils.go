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
	"reflect"
)

func ValueEqual(v1, v2 interface{}) bool {
	return reflect.DeepEqual(v1, v2)
}

func SliceFind(ar interface{}, equal func(i int) bool) interface{} {
	rv := reflect.ValueOf(ar)
	for i := 0; i < rv.Len(); i++ {
		if equal(i) {
			return rv.Index(i)
		}
	}
	return nil
}

func SliceMerge(ar interface{}, v interface{}, equal func(i int) bool) (interface{}, bool) {
	rv := reflect.ValueOf(ar)
	for i := 0; i < rv.Len(); i++ {
		if !equal(i) {
			continue
		}
		if reflect.DeepEqual(rv.Index(i).Interface(), v) {
			return nil, false
		}
		rv.Index(i).Set(reflect.ValueOf(v))
		return nil, true
	}
	return reflect.Append(rv, reflect.ValueOf(v)).Interface(), true
}

func ArrayStringHas(ls []string, s string) bool {
	for _, v := range ls {
		if v == s {
			return true
		}
	}
	return false
}

func ArrayStringEqual(ls1, ls2 []string) bool {
	if len(ls1) != len(ls2) {
		return false
	}
	for _, v := range ls1 {
		if !ArrayStringHas(ls2, v) {
			return false
		}
	}
	return true
}

func ArrayStringUniJoin(ls []string, s string) []string {
	if s != "" {
		for _, v := range ls {
			if v == s {
				return ls
			}
		}
		ls = append(ls, s)
	}
	return ls
}

func JsonEncode(v interface{}) []byte {
	if v != nil {
		b, _ := json.Marshal(v)
		return b
	}
	return nil
}

func AttrAllow(opbase, op uint64) bool {
	return (op & opbase) == op
}

func AttrRemove(opbase, op uint64) uint64 {
	return (opbase | op) - (op)
}

func AttrAppend(opbase, op uint64) uint64 {
	return (opbase | op)
}
