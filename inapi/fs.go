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
	"github.com/lessos/lessgo/types"
)

type FsFile struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Path           string `json:"path,omitempty" toml:"path,omitempty"`
	PathSet        string `json:"pathset,omitempty" toml:"pathset,omitempty"`
	Name           string `json:"name,omitempty" toml:"name,omitempty"`
	Size           int64  `json:"size,omitempty" toml:"size,omitempty"`
	Mime           string `json:"mime,omitempty" toml:"mime,omitempty"`
	Body           string `json:"body,omitempty" toml:"body,omitempty"`
	SumCheck       string `json:"sumcheck,omitempty" toml:"sumcheck,omitempty"`
	IsDir          bool   `json:"isdir,omitempty" toml:"isdir,omitempty"`
	ModTime        string `json:"modtime,omitempty" toml:"modtime,omitempty"`
	Encode         string `json:"encode,omitempty" toml:"encode,omitempty"`
	// Mode     uint32    `json:"mode" toml:"mode"`
}

type FsFileList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Path           string   `json:"path,omitempty" toml:"path,omitempty"`
	Items          []FsFile `json:"items,omitempty" toml:"items,omitempty"`
}
