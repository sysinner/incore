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
	"fmt"
	"testing"
)

type EntrySub struct {
	Value string
}

type Entry struct {
	Name  string
	Value string
	Sub1  EntrySub
	Sub2  *EntrySub
	Map   map[string]string
}

var (
	ar1 = []Entry{
		{Name: "a", Value: "aa"},
		{Name: "b", Value: "bb", Sub1: EntrySub{"SS"}, Sub2: &EntrySub{"SS"}, Map: map[string]string{}},
	}

	a = Entry{
		Name:  "a",
		Value: "aa",
		Map:   map[string]string{},
	}

	b = Entry{
		Name:  "b",
		Value: "bb",
		Map:   map[string]string{},
	}

	bs = Entry{
		Name:  "b",
		Value: "bb",
		Sub1:  EntrySub{"SS"},
		Sub2:  &EntrySub{"SS"},
		Map:   map[string]string{},
	}

	c = Entry{
		Name:  "c",
		Value: "cc",
	}
)

func init() {

	for i := 0; i < 100; i++ {
		ar1[1].Map[fmt.Sprintf("%8d", i)] = fmt.Sprintf("%8d-%8d", i, i)
	}

	for i := 0; i < 100; i++ {
		b.Map[fmt.Sprintf("%8d", i)] = fmt.Sprintf("%8d-%8d", i, i)
	}

	for i := 0; i < 100; i++ {
		bs.Map[fmt.Sprintf("%8d", i)] = fmt.Sprintf("%8d-%8d", i, i)
	}
}

func Test_SliceMerge(t *testing.T) {

	//
	if _, ok := SliceMerge(ar1, a, func(i int) bool {
		return ar1[i].Name == a.Name
	}); !ok {
		t.Fatal("fail sync-merge")
	}

	//
	if _, ok := SliceMerge(ar1, bs, func(i int) bool {
		return ar1[i].Name == b.Name
	}); ok {
		t.Fatal("fail sync-merge")
	}

	//
	if _, ok := SliceMerge(ar1, b, func(i int) bool {
		return ar1[i].Name == b.Name
	}); !ok {
		t.Fatal("fail sync-merge")
	}

	if rs, ok := SliceMerge(ar1, c, func(i int) bool {
		return ar1[i].Name == c.Name
	}); ok && rs != nil {
		ar2 := rs.([]Entry)
		if len(ar2) != 3 {
			t.Fatal("fail sync-merge")
		}
	} else {
		t.Fatal("fail sync-merge")
	}

	c.Name = "b"

	if rs, ok := SliceMerge(ar1, c, func(i int) bool {
		return ar1[i].Name == c.Name
	}); ok {
		if ar1[1].Value != "cc" {
			t.Fatal("fail sync-merge")
		}
		if rs != nil {
			t.Fatal("fail sync-merge")
		}
	} else {
		t.Fatal("fail sync-merge")
	}
}

func Benchmark_SliceMerge(b *testing.B) {

	vb := Entry{
		Name:  "b",
		Value: "bb",
	}

	for i := 0; i < b.N; i++ {
		if _, ok := SliceMerge(ar1, vb, func(i int) bool {
			return ar1[i].Name == vb.Name
		}); ok {
		}
	}
}

func Benchmark_SliceMerge_Map100(b *testing.B) {

	for i := 0; i < b.N; i++ {
		if _, ok := SliceMerge(ar1, bs, func(i int) bool {
			return ar1[i].Name == bs.Name
		}); ok {
		}
	}
}
