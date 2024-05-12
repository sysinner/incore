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

package docker

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/hooto/hlog4g/hlog"

	"github.com/sysinner/injob"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inutils/filerender"
	"github.com/sysinner/incore/status"
	insta "github.com/sysinner/incore/status"
)

type jobBoxImageEntry struct {
	name    string
	path    string
	tag     string
	status  string
	updated int64
}

type BoxImageUpdate struct {
	jobSpec   *injob.JobSpec
	jobSch    *injob.Schedule
	jobImages []*jobBoxImageEntry
	inited    bool
}

func (it *BoxImageUpdate) Spec() *injob.JobSpec {
	if it.jobSpec == nil {
		it.jobSpec = injob.NewJobSpec("host/box/image/update")
	}
	if len(it.jobImages) == 0 {
		// TODO dynamic configuration
		it.jobImages = []*jobBoxImageEntry{
			{
				name: "g3",
				path: "misc/boximages/docker/g3",
				tag:  "sysinner/innerstack-g3:el8",
			},
			{
				name: "g2",
				path: "misc/boximages/docker/g2",
				tag:  "sysinner/innerstack-g2:el7",
			},
			{
				name: "b1",
				path: "misc/boximages/docker/b1",
				tag:  "sysinner/innerstack-b1:v1.0",
			},
			/**
			{
				name: "bg1",
				path: "misc/boximages/docker/bg1",
				tag:  "sysinner/innerstack-bg3:linux",
			},
			*/
		}
	}
	return it.jobSpec
}

func (it *BoxImageUpdate) Status() *injob.Status {
	return nil
}

func (it *BoxImageUpdate) Run(ctx *injob.Context) error {

	if !status.HostletReady() {
		return errors.New("host not ready")
	}

	if !it.inited {

		if insta.Host.Spec != nil && insta.Host.Spec.Platform.Os == "el" {

			script := `sed -i 's/SELINUX\=enforcing/SELINUX\=disabled/g' /etc/selinux/config
setenforce 0
`
			if _, err := exec.Command("sh", "-c", script).Output(); err != nil {
				// skip error
			}

			if _, err := os.Stat("/opt/docker"); err != nil {
				if err = os.Mkdir("/opt/docker", 0755); err != nil {
					return err
				}
			}

			if _, err := os.Stat("/etc/docker/daemon.json"); err != nil {

				os.Mkdir("/etc/docker", 0755)
				js := `{
  "bip": "172.18.0.1/16",
  "data-root": "/opt/docker",
  "registry-mirrors": ["https://registry.docker-cn.com", "https://mirror.ccs.tencentyun.com"]
}`
				if err = filerender.RenderString(js, "/etc/docker/daemon.json", 0644, map[string]interface{}{}); err != nil {
					return err
				}
			}
		}

		if runtime.GOOS == "linux" {
			for _, v := range []string{
				"containerd",
				"docker",
			} {
				if _, err := exec.Command("systemctl", "enable", v).Output(); err != nil {
					hlog.Printf("info", err.Error())
					return err
				}

				if _, err := exec.Command("systemctl", "start", v).Output(); err != nil {
					hlog.Printf("info", err.Error())
					return err
				}
			}
		}
		it.inited = true
	}

	if driver == nil || !driver.inited {
		return errors.New("box/driver not ready #01")
	}

	if err := driver.imageListRefresh(); err != nil {
		return err
	}

	tn := time.Now().Unix()
	n := 0

	for _, v := range it.jobImages {

		if driver.imageSets.Has(v.tag) {
			continue
		}

		if (v.updated + 60) > tn {
			continue
		}

		cmd := exec.Command(config.Prefix + "/" + v.path + "/build")
		cmd.Dir = config.Prefix + "/" + v.path

		hlog.Printf("info", "build/update image %s start ...", v.tag)

		_, err := cmd.Output()
		if err == nil {
			hlog.Printf("info", "build/update image %s ok", v.tag)
			v.updated = time.Now().Unix()
			n += 1
		} else {
			hlog.Printf("info", "build/update image %s fail %s", v.tag, err.Error())
		}
	}

	if n > 0 {
		if err := driver.imageListRefresh(); err != nil {
			return err
		}
	}

	return nil
}

func NewBoxImageUpdateJob() *injob.JobEntry {
	return injob.NewJobEntry(&BoxImageUpdate{},
		injob.NewSchedule().OnBoot(true).EveryTimeCycle(injob.Weekday, 1))
}
