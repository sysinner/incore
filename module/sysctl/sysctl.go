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

package sysctl

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/injob/v1"
)

type SysctlJob struct {
	spec   *injob.JobSpec
	inited bool
}

func (it *SysctlJob) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("incore/sysctl")
	}
	return it.spec
}

func (it *SysctlJob) Status() *injob.Status {
	return nil
}

func (it *SysctlJob) Run(ctx *injob.Context) error {

	if runtime.GOOS == "linux" {

		{
			for k, v := range map[string]string{
				"net.ipv4.ip_forward":          "1",
				"net.ipv4.ip_local_port_range": "32768 60999",
				"net.ipv4.tcp_fin_timeout":     "30",
				"net.ipv4.tcp_keepalive_time":  "3600",
				"net.ipv4.tcp_syncookies":      "1",
				"net.ipv4.tcp_tw_reuse":        "2",

				/**
				// maximum number of file handles that the Linux kernel will allocate
				"fs.file-max": "200000",

				// maximum number of file-handles a process can allocate
				"fs.nr_open": "10240000",
				*/
			} {
				if err := configWrite(k, v); err != nil {
					return err
				}
			}
		}

		hlog.Printf("info", "sysctl reset ok")
	}

	return nil
}

func NewSysctlJob() *injob.JobEntry {
	return injob.NewJobEntry(&SysctlJob{},
		injob.NewSchedule().OnBoot(true),
	)
}

const (
	basePath = "/proc/sys/"
)

func nameToPath(name string) string {
	return filepath.Join(basePath, strings.Replace(name, ".", "/", -1))
}

func fileWrite(path, value string) error {
	return ioutil.WriteFile(path, []byte(value), 0644)
}

func configWrite(name, value string) error {
	return fileWrite(nameToPath(name), value)
}
