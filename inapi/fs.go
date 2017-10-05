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
	"github.com/lessos/lessgo/types"
)

type FsFile struct {
	types.TypeMeta `json:",inline"`
	Path           string `json:"path,omitempty"`
	PathSet        string `json:"pathset,omitempty"`
	Name           string `json:"name,omitempty"`
	Size           int64  `json:"size,omitempty"`
	Mime           string `json:"mime,omitempty"`
	Body           string `json:"body,omitempty"`
	SumCheck       string `json:"sumcheck,omitempty"`
	IsDir          bool   `json:"isdir,omitempty"`
	ModTime        string `json:"modtime,omitempty"`
	Encode         string `json:"encode,omitempty"`
	// Mode     uint32    `json:"mode"`
}

type FsFileList struct {
	types.TypeMeta `json:",inline"`
	Path           string   `json:"path,omitempty"`
	Items          []FsFile `json:"items,omitempty"`
}
