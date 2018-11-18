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

package agtapi

type VcsStatusItem struct {
	Dir         string `json:"dir"` // primary key
	Url         string `json:"url"`
	Branch      string `json:"branch"`
	Action      uint32 `json:"action"`
	Msg         string `json:"msg"`
	Version     string `json:"version"`
	PrevVersion string `json:"prev_version"`
	Updated     uint32 `json:"updated"`
	AppSpecId   string `json:"app_spce_id"`
}

type VcsStatusItems []*VcsStatusItem

func (ls *VcsStatusItems) Get(id string) *VcsStatusItem {
	for _, v := range *ls {
		if v.Dir == id {
			return v
		}
	}
	return nil
}

func (ls *VcsStatusItems) Set(v2 *VcsStatusItem) {

	for _, v := range *ls {
		if v.Dir == v2.Dir {
			v.Url = v2.Url
			v.Branch = v2.Branch
			v.Action = v2.Action
			v.Msg = v2.Msg
			v.Version = v2.Version
			v.Updated = v2.Updated
			v.AppSpecId = v2.AppSpecId
			return
		}
	}

	*ls = append(*ls, v2)
}

func (ls *VcsStatusItems) Del(id string) {

	for i, v := range *ls {
		if v.Dir == id {
			*ls = append((*ls)[0:i], (*ls)[i+1:]...)
			break
		}
	}
}
