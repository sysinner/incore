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

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/hooto/httpsrv/deps/go.net/websocket"
	"github.com/lessos/lessgo/encoding/json"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inagent/executor"
	"github.com/sysinner/incore/inagent/status"
	"github.com/sysinner/incore/inagent/v1"
	"github.com/sysinner/incore/inagent/vcs"
	"github.com/sysinner/incore/inapi"
)

const (
	addr_sock        = "unix:/home/action/.sysinner/inagent.sock"
	pod_instance_cfg = "/home/action/.sysinner/pod_instance.json"
	home_dir         = "/home/action"
)

var (
	pod_id    = ""
	init_dirs = []string{
		"/home/action/local/bin",
		"/home/action/local/share",
		"/home/action/local/profile.d",
		"/home/action/var/tmp",
		"/home/action/var/log",
		"/home/action/.ssh",
	}
)

func Start() error {

	//
	pod_id = strings.TrimSpace(os.Getenv("POD_ID"))
	if !inapi.PodIdReg.MatchString(pod_id) {
		return errors.New("ENV POD_ID Not Match")
	}

	//
	for _, v := range init_dirs {
		if err := os.MkdirAll(v, 0755); err != nil {
			return err
		}
	}

	//
	if _, err := user.Lookup(config.User.Username); err != nil {
		if _, err = exec.Command(
			"/usr/sbin/useradd",
			"-d", "/home/action",
			"-s", "/bin/bash",
			"-u", config.User.Uid, config.User.Username,
		).Output(); err != nil {
			return err
		}
	}

	//
	syscall.Setgid(2048)
	syscall.Setuid(2048)
	syscall.Chdir("/home/action")

	//
	hlog.LogDirSet("/home/action/var/log")

	hlog.Printf("info", "inagent/daemon started")

	//
	httpsrv.GlobalService.Config.HttpAddr = addr_sock

	httpsrv.GlobalService.HandlerRegister(
		"/in/v1/pb/termws",
		websocket.Handler(v1.TerminalWsOpenAction))

	httpsrv.GlobalService.ModuleRegister("/in/v1/", v1.NewModule())

	go httpsrv.GlobalService.Start()

	worker()
	return errors.New("httpsrv exit")
}

func worker() {

	var (
		inited = false
	)

	for {
		if inited {
			time.Sleep(10e9)
		}
		inited = true

		workerEntry()
	}
}

func workerEntry() {

	var (
		pod inapi.PodRep
		err error
	)

	if err = json.DecodeFile(home_dir+"/.sysinner/pod_instance.json", &pod); err != nil {
		hlog.Printf("error", err.Error())
		return
	}

	defer func() {
		json.EncodeToFile(status.OpLog, home_dir+"/.sysinner/box_status.json", "  ")
	}()

	vcsn, err := vcs.Action(&pod)
	if err != nil {
		hlog.Printf("error", err.Error())
		return
	}
	if vcsn != 0 {
		// hlog.Printf("info", "VCS pending")
		return
	}

	//
	for _, v := range status.VcsStatuses {

		if v.Version == "" || v.Version == v.PrevVersion {
			continue
		}

		if v.PrevVersion != "" {
			if v2 := status.VcsRepos.Get(v.Dir); v2 != nil {
				if v2.HookPodRestart {
					executor.StopAll(&pod, "/home/action")
					hlog.Printf("info", "plan to restart pod, hook/vcs/update %s",
						v.Version)
					hlog.Flush()
					os.Exit(0)
				} else if v2.HookExecRestart != "" {
					hlog.Printf("info", "plan to restart executor (%s), hook/vcs/update %s",
						v2.HookExecRestart, v.Version)
					executor.Restart(&pod, "/home/action", v.AppSpecId, v2.HookExecRestart)
				}
			}
		}

		v.PrevVersion = v.Version
	}

	if err = executor.Runner(&pod, "/home/action"); err != nil {
		hlog.Printf("error", err.Error())
		return
	}
}
