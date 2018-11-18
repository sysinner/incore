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
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	VcsRepoGitUrlReg = regexp.MustCompile(`^(https?:\/\/)([\w\-_\.\/]+)(\.git)$`)
	VcsCloneDirReg   = regexp.MustCompile(`^[a-zA-Z0-9\.\/\-_]{1,50}$`)
	VcsGitVerReg     = regexp.MustCompile(`^[a-f0-9]{30,50}$`)
)

const (
	VcsActionOK     uint32 = 1 << 1
	VcsActionER     uint32 = 1 << 2
	VcsActionUnAuth uint32 = 1 << 3
	VcsActionPull   uint32 = 1 << 4
)

type VcsRepoItem struct {
	Dir             string `json:"dir"` // primary key
	Url             string `json:"url"`
	Branch          string `json:"branch"`
	Plan            string `json:"plan"`
	AuthUser        string `json:"auth_user,omitempty"`
	AuthPass        string `json:"auth_pass,omitempty"`
	HookExecRestart string `json:"hook_exec_restart,omitempty"`
	HookPodRestart  bool   `json:"hook_pod_restart,omitempty"`
}

func (it *VcsRepoItem) Valid() error {

	it.Dir = strings.TrimLeft(filepath.Clean("/"+it.Dir), "/")

	if !VcsCloneDirReg.MatchString(it.Dir) {
		return errors.New("Invalid VCS Dir")
	}

	if !VcsRepoGitUrlReg.MatchString(it.Url) {
		return errors.New("Invalid VCS Repo URL")
	}

	return nil
}

type VcsRepoItems []*VcsRepoItem

func (ls *VcsRepoItems) Get(id string) *VcsRepoItem {
	for _, v := range *ls {
		if v.Dir == id {
			return v
		}
	}
	return nil
}

func (ls *VcsRepoItems) Set(v2 *VcsRepoItem) {

	for _, v := range *ls {
		if v.Dir == v2.Dir {
			v.Url = v2.Url
			v.Branch = v2.Branch
			v.Plan = v2.Plan
			v.AuthUser = v2.AuthUser
			v.AuthPass = v2.AuthPass
			v.HookExecRestart = v2.HookExecRestart
			v.HookPodRestart = v2.HookPodRestart
			return
		}
	}

	*ls = append(*ls, v2)
}

func (ls *VcsRepoItems) Del(id string) {

	for i, v := range *ls {
		if v.Dir == id {
			*ls = append((*ls)[0:i], (*ls)[i+1:]...)
			break
		}
	}
}
