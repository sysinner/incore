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

package executor

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/logger"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/lpagent/status"
)

func Runner(home_dir string) {

	for {

		time.Sleep(1e9)

		var pod losapi.Pod
		if err := json.DecodeFile(home_dir+"/.los/pod_instance.json", &pod); err != nil {
			logger.Printf("error", err.Error())
			continue
		}

		if pod.Apps == nil || len(pod.Apps) < 0 {
			logger.Printf("debug", "No Apps Found")
			continue
		}

		data_maps := map[string]string{}

		for _, app := range pod.Apps {

			for _, p := range app.Spec.Packages {
				data_maps[fmt.Sprintf("lpm_prefix_%s", strings.Replace(p.Name, "-", "_", -1))] = fmt.Sprintf("/usr/los/%s/%s", p.Name, p.Version)
			}
		}

		for _, app := range pod.Apps {

			for _, ve := range app.Spec.Executors {

				logger.Printf("debug", "AppExec %s", ve.Name)

				ve.Name = types.NameIdentifier(fmt.Sprintf("%s/%s", app.Spec.Meta.Name, ve.Name))

				status.Executors.Sync(ve)
				executor_action(ve, data_maps)
			}
		}
	}
}

func executor_action(etr losapi.Executor, dms map[string]string) {

	es := status.Statuses.Get(etr.Name)

	//
	if es == nil {

		es = &losapi.ExecutorStatus{
			Name:    etr.Name,
			Created: types.MetaTimeNow(),
			Vendor:  etr.Vendor,
		}

		status.Statuses.Sync(es)
	}

	//
	if es.Cmd != nil {

		if es.Cmd.Process != nil {

			if es.Cmd.ProcessState == nil {
				es.Action.Append(losapi.ExecutorActionRunning)
			}
		}

		if es.Cmd.ProcessState != nil && es.Cmd.ProcessState.Exited() {

			es.Action.Remove(losapi.ExecutorActionRun)
			es.Action.Remove(losapi.ExecutorActionRunning)

			es.Action.Append(losapi.ExecutorActionDone)

			if es.Cmd.ProcessState.Success() {
				es.Action.Append(losapi.ExecutorActionSuccess)
			} else {
				es.Action.Append(losapi.ExecutorActionFailed)
			}

			// logger.Printf("info", "executor:%s status: %s",
			// 	etr.Name, es.Action.String())

			if es.Cmd.Process != nil {
				es.Cmd.Process.Kill()
				time.Sleep(5e8)
			}

			es.Cmd = nil
			es.Updated = types.MetaTimeNow()
		}
	}

	//
	// logger.Printf("info", "executor:%s action:%s", etr.Name, es.Action.String())
	if es.Action.Allow(losapi.ExecutorActionRun) ||
		es.Action.Allow(losapi.ExecutorActionRunning) {

		// logger.Printf("info", "executor:%s Cmd.ProcessState Pending SKIP", etr.Name)
		return
	}

	// Exec Planner
	{
		//
		if etr.Plan.OnBoot &&
			es.Plan.Updated < 1 &&
			!es.Action.Allow(losapi.ExecutorActionRun) &&
			!es.Action.Allow(losapi.ExecutorActionDone) {

			es.Action.Append(losapi.ExecutorActionRun)

			logger.Printf("warn", "executor:%s Plan.OnBoot Run", etr.Name)
		}

		//
		if etr.Plan.OnCalendar != nil &&
			!es.Action.Allow(losapi.ExecutorActionRun) {
			// TODO
		}

		//
		if etr.Plan.OnTick > 0 &&
			!es.Action.Allow(losapi.ExecutorActionRun) {

			if etr.Plan.OnTick < 60 {
				etr.Plan.OnTick = 60
			}

			if (time.Now().UTC().Unix() - es.Plan.Updated.Time().Unix()) > int64(etr.Plan.OnTick) {

				es.Action.Append(losapi.ExecutorActionRun)

				logger.Printf("info", "executor:%s Plan.OnTick", etr.Name)
			}
		}

		//
		if etr.Plan.OnFailed != nil &&
			!es.Action.Allow(losapi.ExecutorActionRun) &&
			es.Action.Allow(losapi.ExecutorActionFailed) {

			retry_sec := etr.Plan.OnFailed.RetrySec.Seconds()
			if retry_sec < 1 {
				retry_sec = 10
			}

			if es.Plan.Updated > 0 &&
				(etr.Plan.OnFailed.RetryMax == -1 ||
					es.Plan.OnFailedRetryNum < etr.Plan.OnFailed.RetryMax) &&
				(time.Now().UTC().Unix()-es.Plan.Updated.Time().Unix()) > retry_sec {

				es.Action.Append(losapi.ExecutorActionRun)
				es.Plan.OnFailedRetryNum++

				logger.Printf("warn", "executor:%s Plan.OnFailed Retry %d",
					etr.Name, es.Plan.OnFailedRetryNum)
			}
		}
	}

	if !es.Action.Allow(losapi.ExecutorActionRun) {
		return
	}

	//
	es.Plan.Updated = types.MetaTimeNow()
	if es.Cmd == nil {
		es.Cmd = exec.Command("/bin/bash", "--rcfile", "/home/action/.bashrc")
	}

	//
	/*
		sets := map[string]string{}
		for _, v := range etr.Packages {
			sets[fmt.Sprintf("lpm_prefix_%s", v.Name)] = fmt.Sprintf("/usr/los/%s/%s", v.Name, v.Version)
			logger.Printf("info", fmt.Sprintf("/usr/los/%s/%s", v.Name, v.Version))
		}
	*/

	//
	tpl, err := template.New("s").Parse(etr.ExecStart)
	if err != nil {
		logger.Printf("error", "executor:%s template.Parse E:%s",
			etr.Name, err.Error())
		return
	}

	//
	var tplout bytes.Buffer
	if err := tpl.Execute(&tplout, dms); err != nil {
		logger.Printf("error", "executor:%s template.Execute E:%s",
			etr.Name, err.Error())
		return
	}

	//
	if err := executor_cmd(es.Name.String(), es.Cmd, tplout.String()); err != nil {
		logger.Printf("error", "executor:%s CMD E:%s",
			etr.Name, err.Error())
		return
	} else {
		logger.Printf("info", "executor:%s running", etr.Name)
	}
}

func executor_cmd(name string, cmd *exec.Cmd, script string) error {

	if cmd == nil {
		return errors.New("No Command INIT")
	}

	if cmd.Process != nil && cmd.ProcessState == nil {
		return errors.New("Command Running")
	}

	if cmd.ProcessState != nil {
		return nil
	}

	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	// in.Write([]byte("set -e\nset -o pipefail\n" + script + "\nexit\n"))
	in.Write([]byte("set -e\nset -o pipefail\n" + script + "\nexit\n"))
	in.Close()

	// cmd.Stdin = strings.NewReader("set -e\nset -o pipefail\n" + script + "\nexit\n")

	if err := cmd.Start(); err != nil {
		return err
	}

	go cmd.Wait()

	return nil
}
