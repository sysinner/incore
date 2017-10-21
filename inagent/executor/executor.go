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

package executor

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/inagent/status"
	"github.com/sysinner/incore/inapi"
)

func oplog_name(name string) string {
	return "box/executor/" + name
}

func Runner(home_dir string) {

	for {

		time.Sleep(1e9)

		var pod inapi.Pod
		if err := json.DecodeFile(home_dir+"/.sysinner/pod_instance.json", &pod); err != nil {
			hlog.Printf("error", err.Error())
			continue
		}

		if pod.Apps == nil || len(pod.Apps) < 0 {
			hlog.Printf("debug", "No Apps Found")
			continue
		}

		data_maps := map[string]string{}

		for _, app := range pod.Apps {

			for _, p := range app.Spec.Packages {
				data_maps[fmt.Sprintf("inpack_prefix_%s", strings.Replace(p.Name, "-", "_", -1))] = fmt.Sprintf("/usr/sysinner/%s/%s", p.Name, p.Version)
			}
		}

		for _, app := range pod.Apps {

			for _, ve := range app.Spec.Executors {

				hlog.Printf("debug", "AppExec %s", ve.Name)

				ve.Name = types.NameIdentifier(fmt.Sprintf("%s/%s", app.Spec.Meta.Name, ve.Name))

				status.Executors.Sync(ve)
				if sts, msg := executor_action(ve, data_maps, app.Operate.Action); sts != "" {
					status.OpLog.LogSet(pod.Operate.Version, oplog_name(string(ve.Name)), sts, msg)
				}
			}
		}

		json.EncodeToFile(status.OpLog, home_dir+"/.sysinner/box_status.json", "  ")
	}
}

func executor_action(etr inapi.Executor, dms map[string]string, op_action uint32) (string, string) {

	es := status.Statuses.Get(etr.Name)
	op_status, op_msg := "", ""

	//
	if es == nil {

		es = &inapi.ExecutorStatus{
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
				es.Action.Append(inapi.ExecutorActionPending)
			}
		}

		if es.Cmd.ProcessState != nil && es.Cmd.ProcessState.Exited() {

			es.Action.Remove(inapi.ExecutorActionPending)

			if es.Cmd.ProcessState.Success() {
				es.Action.Remove(inapi.ExecutorActionFailed)
				op_status, op_msg = inapi.PbOpLogOK, "process ok"
			} else {
				es.Action.Append(inapi.ExecutorActionFailed)
				op_status, op_msg = inapi.PbOpLogError, "process error "+es.Cmd.ProcessState.String()
			}

			if es.Action.Allow(inapi.ExecutorActionStart) {
				es.Action.Remove(inapi.ExecutorActionStart)
				es.Action.Append(inapi.ExecutorActionStarted)
			}

			if es.Action.Allow(inapi.ExecutorActionStop) {
				es.Action.Remove(inapi.ExecutorActionStop)
				es.Action.Append(inapi.ExecutorActionStopped)
			}

			hlog.Printf("info", "executor:%s done status: %s",
				etr.Name, es.Action.String())

			if es.Cmd.Process != nil {
				es.Cmd.Process.Kill()
				time.Sleep(5e8)
			}

			es.Cmd = nil
			es.Updated = types.MetaTimeNow()

			return op_status, op_msg
		}
	}

	if inapi.OpActionAllow(op_action, inapi.OpActionStop) &&
		es.Action.Allow(inapi.ExecutorActionStopped) {
		return inapi.PbOpLogOK, "stopped"
	}

	//
	// hlog.Printf("info", "executor:%s action:%s", etr.Name, es.Action.String())
	if es.Action.Allow(inapi.ExecutorActionPending) {
		hlog.Printf("info", "executor:%s Cmd.ProcessState Pending SKIP", etr.Name)
		return inapi.PbOpLogWarn, "pending"
	}

	/*
		if inapi.OpActionAllow(op_action, inapi.OpActionStop) {
			es.Action.Append(inapi.ExecutorActionStop)
		}
	*/

	// Exec Planner
	if inapi.OpActionAllow(op_action, inapi.OpActionStop) {
		es.Action = inapi.ExecutorActionStop
	} else if inapi.OpActionAllow(op_action, inapi.OpActionStart) {

		es.Action.Remove(inapi.ExecutorActionStop)
		es.Action.Remove(inapi.ExecutorActionStopped)

		//
		if etr.Plan.OnBoot &&
			es.Plan.Updated < 1 &&
			!es.Action.Allow(inapi.ExecutorActionStarted) {

			es.Action.Append(inapi.ExecutorActionStart)

			hlog.Printf("warn", "executor:%s Plan.OnBoot Exec", etr.Name)
		}

		//
		if etr.Plan.OnCalendar != nil &&
			!es.Action.Allow(inapi.ExecutorActionStart) {
			// TODO
		}

		//
		if etr.Plan.OnTick > 0 &&
			!es.Action.Allow(inapi.ExecutorActionStart) {

			if etr.Plan.OnTick < 60 {
				etr.Plan.OnTick = 60
			}

			if (time.Now().UTC().Unix() - es.Plan.Updated.Time().Unix()) > int64(etr.Plan.OnTick) {

				es.Action.Append(inapi.ExecutorActionStart)
				es.Action.Remove(inapi.ExecutorActionStarted)

				hlog.Printf("info", "executor:%s Plan.OnTick", etr.Name)
			}
		}

		//
		if etr.Plan.OnFailed != nil &&
			!es.Action.Allow(inapi.ExecutorActionStart) &&
			es.Action.Allow(inapi.ExecutorActionFailed) {

			retry_sec := etr.Plan.OnFailed.RetrySec.Seconds()
			if retry_sec < 1 {
				retry_sec = 10
			}

			if es.Plan.Updated > 0 &&
				(etr.Plan.OnFailed.RetryMax == -1 ||
					es.Plan.OnFailedRetryNum < etr.Plan.OnFailed.RetryMax) &&
				(time.Now().UTC().Unix()-es.Plan.Updated.Time().Unix()) > retry_sec {

				es.Action.Append(inapi.ExecutorActionStart)
				es.Action.Remove(inapi.ExecutorActionStarted)

				es.Plan.OnFailedRetryNum++

				hlog.Printf("warn", "executor:%s Plan.OnFailed Retry %d",
					etr.Name, es.Plan.OnFailedRetryNum)
			}
		}

	} else {
		return "", ""
	}

	//
	script := ""
	if es.Action.Allow(inapi.ExecutorActionStart) {
		script = etr.ExecStart
	} else if es.Action.Allow(inapi.ExecutorActionStop) {
		script = etr.ExecStop
	} else {
		return "", ""
	}

	//
	es.Action.Append(inapi.ExecutorActionPending)
	es.Plan.Updated = types.MetaTimeNow()
	if es.Cmd == nil {
		es.Cmd = exec.Command("/bin/bash", "--rcfile", "/home/action/.bashrc")
	}

	//
	/*
		sets := map[string]string{}
		for _, v := range etr.Packages {
			sets[fmt.Sprintf("inpack_prefix_%s", v.Name)] = fmt.Sprintf("/usr/sysinner/%s/%s", v.Name, v.Version)
			hlog.Printf("info", fmt.Sprintf("/usr/sysinner/%s/%s", v.Name, v.Version))
		}
	*/

	//
	tpl, err := template.New("s").Parse(script)
	if err != nil {
		hlog.Printf("error", "executor:%s template.Parse E:%s",
			etr.Name, err.Error())
		return inapi.PbOpLogError, err.Error()
	}

	//
	var tplout bytes.Buffer
	if err := tpl.Execute(&tplout, dms); err != nil {
		hlog.Printf("error", "executor:%s template.Execute E:%s",
			etr.Name, err.Error())
		return inapi.PbOpLogError, err.Error()
	}

	//
	if err := executor_cmd(es.Name.String(), es.Cmd, tplout.String()); err != nil {
		hlog.Printf("error", "executor:%s CMD E:%s",
			etr.Name, err.Error())
		return inapi.PbOpLogError, err.Error()
	} else {
		hlog.Printf("info", "executor:%s pending", etr.Name)
	}

	return inapi.PbOpLogWarn, "pending"
}

func executor_cmd(name string, cmd *exec.Cmd, script string) error {

	if cmd == nil {
		return errors.New("No Command INIT")
	}

	if cmd.Process != nil && cmd.ProcessState == nil {
		return errors.New("Command Pending")
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
