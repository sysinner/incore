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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/inagent/status"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils/tplrender"
)

func oplogName(name string) string {
	return "box/exec/" + name
}

func keyenc(k string) string {
	return strings.Replace(strings.Replace(k, "/", "__", -1), "-", "_", -1)
}

func repParams(pod *inapi.PodRep) map[string]string {

	sets := map[string]string{}

	sets["pod__replica__rep_id"] = fmt.Sprintf("%d", pod.Replica.RepId)
	sets["pod__operate__replica_cap"] = fmt.Sprintf("%d", pod.Operate.ReplicaCap)

	for _, app := range pod.Apps {

		for _, op := range app.Operate.Options {

			for _, item := range op.Items {
				var (
					ckey = keyenc(fmt.Sprintf("%s__%s", op.Name, item.Name))
					key  = keyenc(fmt.Sprintf("app__%s__option__%s", app.Spec.Meta.ID, ckey))
				)
				sets[key] = item.Value
				if _, ok := sets[ckey]; !ok {
					sets[ckey] = item.Value
				}
			}
		}

		for _, p := range app.Operate.Services {

			if p.Name == "" || len(p.Endpoints) < 1 {
				continue
			}

			key := keyenc(fmt.Sprintf("pod__oprep__port__%s__",
				p.Name,
			))
			sets[key+"lan_addr"] = p.Endpoints[0].Ip
			sets[key+"host_port"] = fmt.Sprintf("%d", p.Endpoints[0].Port)
		}

		for _, p := range app.Spec.Packages {
			sets[fmt.Sprintf("inpack_prefix_%s", strings.Replace(p.Name, "-", "_", -1))] = fmt.Sprintf("/usr/sysinner/%s/%s", p.Name, p.Version)
		}
	}

	return sets
}

func execStatusName(id string, name types.NameIdentifier) types.NameIdentifier {
	return types.NameIdentifier(fmt.Sprintf("%s/%s", id, name))
}

func execAction(pod *inapi.PodRep, home_dir, appspec_id, exec_name string, action uint32) error {

	if pod.Apps == nil || len(pod.Apps) < 1 {
		return nil
	}

	sets := repParams(pod)

	for i := 1; i < 10; i++ {

		n := 0

		for _, app := range pod.Apps {
			if appspec_id != "" && appspec_id != app.Spec.Meta.ID {
				continue
			}
			for _, ve := range app.Spec.Executors {
				if exec_name != "" && exec_name != ve.Name.String() {
					continue
				}
				n += 1
				esName := execStatusName(app.Spec.Meta.ID, ve.Name)
				if sts, _ := executorAction(esName, ve, sets, inapi.OpActionStop); sts == inapi.PbOpLogOK {
					n -= 1
				}
			}
		}

		if n == 0 {
			return nil
		}

		time.Sleep(time.Duration(i) * time.Second)
	}

	return errors.New("timeout in execAction")
}

func Restart(pod *inapi.PodRep, home_dir, appspec_id, exec_name string) error {
	if err := execAction(pod, home_dir, appspec_id, exec_name, inapi.OpActionStop); err != nil {
		return err
	}
	return execAction(pod, home_dir, appspec_id, exec_name, inapi.OpActionStart)
}

func StopAll(pod *inapi.PodRep, home_dir string) error {
	return execAction(pod, home_dir, "", "", inapi.OpActionStop)
}

func Runner(pod *inapi.PodRep, home_dir string) error {

	if err := executorInitSSH(pod); err != nil {
		return err
	}

	if pod.Apps != nil && len(pod.Apps) > 0 {

		sets := repParams(pod)

		for priority := uint8(0); priority <= inapi.SpecExecutorPriorityMax; {

			pdone := 0

			for _, app := range pod.Apps {

				if !inapi.OpActionAllow(app.Operate.Action, inapi.OpActionStart) &&
					!inapi.OpActionAllow(app.Operate.Action, inapi.OpActionStop) {
					continue
				}

				for _, ve := range app.Spec.Executors {

					if priority != ve.Priority {
						continue
					}

					pdone++

					esName := execStatusName(app.Spec.Meta.ID, ve.Name)

					if es := status.Statuses.Get(esName); es != nil {
						if es.Action.Allow(inapi.ExecutorActionStarted) ||
							es.Action.Allow(inapi.ExecutorActionStopped) {
							pdone--
						}
					}

					status.Executors.Sync(ve)
					if sts, msg := executorAction(esName, ve, sets, app.Operate.Action); sts != "" {
						status.OpLog.LogSet(pod.Operate.Version, oplogName(string(esName)), sts, msg)
					}
				}
			}

			if pdone == 0 {
				priority++
			} else {
				time.Sleep(1e9)
			}
		}
	}

	return nil
}

var (
	sshInitVersion uint32 = 0
	sshInitStart          = `
if pidof sshd; then
    exit 0
fi

/usr/sbin/sshd -p %d
`
)

func executorInitSSH(pod *inapi.PodRep) error {

	if pod.Operate.Access == nil {
		return nil
	}

	if pod.Operate.Access.SshOn {

		//
		if sshInitVersion < pod.Operate.Version {

			for _, v := range []string{"rsa", "ecdsa", "ed25519"} {
				if err := executorInitSSHKeygen(v); err != nil {
					return err
				}
			}

			fp, err := os.OpenFile("/home/action/.ssh/authorized_keys", os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return err
			}
			defer fp.Close()

			fp.Seek(0, 0)
			fp.Truncate(0)

			if _, err = fp.WriteString(pod.Operate.Access.SshKey + "\n"); err != nil {
				return err
			}
		}

		//
		port := 2022
		if pod.Apps.NetworkModeHost() {
			p := pod.Replica.Ports.Get(2022)
			if p == nil || p.HostPort < 1024 {
				return errors.New("no ssh/port found")
			}
			port = int(p.HostPort)
		}

		//
		if _, err := exec.Command("/bin/sh", "-c", fmt.Sprintf(sshInitStart, port)).CombinedOutput(); err != nil {
			return err
		}

	} else if sshInitVersion > 0 && sshInitVersion < pod.Operate.Version {
		exec.Command("/bin/sh", "-c", "killall sshd").Output()
	}

	if sshInitVersion != pod.Operate.Version {
		sshInitVersion = pod.Operate.Version
		hlog.Printf("info", "sshInitVersion %d", pod.Operate.Version)
	}

	return nil
}

func executorInitSSHKeygen(name string) error {

	_, err := os.Stat("/home/action/.ssh")
	if err != nil {
		os.Mkdir("/home/action/.ssh", 0755)
	}

	path := fmt.Sprintf("/home/action/.ssh/ssh_host_%s_key", name)
	if _, err = os.Stat(path); err != nil {
		_, err = exec.Command("sh", "-c", "ssh-keygen -t "+name+" -f "+path+" -N ''").CombinedOutput()
	}

	return err
}

func executorAction(esName types.NameIdentifier, etr inapi.Executor, dms map[string]string, op_action uint32) (string, string) {

	es := status.Statuses.Get(esName)
	op_status, op_msg := "", ""

	//
	if es == nil {

		es = &inapi.ExecutorStatus{
			Name:    esName,
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
				esName, es.Action.String())

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
		hlog.Printf("debug", "executor:%s Cmd.ProcessState Pending SKIP", esName)
		return inapi.PbOpLogInfo, "pending"
	}

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

			hlog.Printf("warn", "executor:%s Plan.OnBoot Exec", esName)
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

				hlog.Printf("info", "executor:%s Plan.OnTick", esName)
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
					esName, es.Plan.OnFailedRetryNum)
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
		es.Cmd = exec.Command("bash", "--rcfile", "/home/action/.bashrc")
	}

	//
	bs, err := tplrender.Render(script, dms)
	if err != nil {
		hlog.Printf("error", "executor:%s template.Execute E:%s",
			esName, err.Error())
		return inapi.PbOpLogError, err.Error()
	}
	vars := ""
	for k, v := range dms {
		if vars != "" {
			vars += ","
		}
		vars += fmt.Sprintf("%s=%s", k, v)
	}
	hlog.Printf("debug", "executor %s, vars %s, exec {{{{%s}}}}",
		esName, vars, string(bs))

	//
	if err := executorCmd(esName, es.Cmd, string(bs)); err != nil {
		hlog.Printf("error", "executor:%s CMD E:%s",
			esName, err.Error())
		return inapi.PbOpLogError, err.Error()
	} else {
		// hlog.Printf("info", "executor:%s pending", esName)
	}

	return inapi.PbOpLogInfo, "pending"
}

func executorCmd(name types.NameIdentifier, cmd *exec.Cmd, script string) error {

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
	in.Write([]byte("source /home/action/.bashrc\nset -e\nset -o pipefail\n" + script + "\nexit\n"))
	in.Close()

	// hlog.Printf("info", "executor:%s cmd:{{{%s}}}", name, script)

	// cmd.Stdin = strings.NewReader("set -e\nset -o pipefail\n" + script + "\nexit\n")

	if err := cmd.Start(); err != nil {
		return err
	}

	go cmd.Wait()

	return nil
}
