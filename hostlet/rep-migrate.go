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

package hostlet

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"

	inConf "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils/filerender"
	"github.com/sysinner/incore/status"
)

var (
	rsyncdInited        = false
	rsyncInited         = false
	rsyncdActiveSecrets types.KvPairs
	rsyncdActiveModules types.KvPairs
)

const (
	rsyncdSecretsTemplate = "{{ range $v := .items }}{{$v.Key}}:{{$v.Value}}\n{{ end }}"
	rsyncdConfTemplate    = `#
port = {{.server_port}} 
uid = root
gid = root
use chroot = yes
max connections = 10

pid file = {{.prefix}}/var/rsyncd/rsyncd.pid
lock file = {{.prefix}}/var/rsyncd/rsyncd.lock
log file = {{.prefix}}/var/rsyncd/rsyncd.log

timeout = 300

# &include {{.prefix}}/etc/rsyncd/rsyncd.d

{{ range $item := .items }}
[{{$item.User}}]
path = {{$item.Dir}}
read only = yes
list = yes
auth users = {{$item.User}}
secrets file = {{$.prefix}}/etc/rsyncd/rsyncd.secrets

{{ end }}
`
)

func podRepMigrate(inst *napi.BoxInstance) bool {

	if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionMigrate) {
		return false
	}

	// Migrate Out
	if inst.Replica.Node == status.Host.Meta.Id && inst.Replica.Next != nil {

		if !inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStopped) {
			return false
		}

		if err := podRepMigrateOut(inst); err != nil {
			hlog.Printf("warn", "pod %s, rep %d, migrate out err %s",
				inst.PodID, inst.Replica.RepId, err.Error())
		}

		return true
	}

	// Migrate In
	if inst.Replica.Next == nil && inst.Replica.Node == status.Host.Meta.Id {

		// hlog.Printf("warn", "pod %s, rep %d", inst.PodID, inst.Replica.RepId)

		if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionRunning) {
			// hlog.Printf("warn", "pod %s, rep %d", inst.PodID, inst.Replica.RepId)
			return false
		}

		if err := podRepMigrateIn(inst); err != nil {
			hlog.Printf("warn", "pod %s, rep %d, migrate in err %s",
				inst.PodID, inst.Replica.RepId, err.Error())
		}

		return true
	}

	return true
}

var (
	podRepMigrateInPending = false
	podRepMigrateInActives = map[string]int64{}
	podRepMigrateMu        sync.Mutex
)

func podRepMigrateIn(inst *napi.BoxInstance) error {

	podRepMigrateMu.Lock()
	defer podRepMigrateMu.Unlock()

	// hlog.Printf("info", "pod %s, rep %d, migrate in done", inst.PodID, inst.Replica.RepId)

	if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionDestroy) ||
		inapi.OpActionAllow(inst.Status.Action, inapi.OpActionMigrated) {
		// hlog.Printf("info", "pod %s, rep %d, migrate in done", inst.PodID, inst.Replica.RepId)
		return nil
	}

	// hlog.Printf("info", "pod %s, rep %d, migrate in", inst.PodID, inst.Replica.RepId)

	if podRepMigrateInPending {
		return nil
	}

	prevAddr, prevAuth := "", ""

	// inapi.ObjPrint("a", inst.Replica)

	if opt, ok := inst.Replica.Options.Get("rsync/host"); !ok {
		return errors.New("options rsync/host not found")
	} else {
		prevAddr = opt.String()
	}

	if opt, ok := inst.Replica.Options.Get("rsync/auth"); !ok {
		return errors.New("options rsync/auth not found")
	} else {
		prevAuth = opt.String()
	}

	if !rsyncInited {
		exec.Command("install", "/usr/bin/rsync",
			inConf.Prefix+"/bin/rsync-client").Output()
	}

	hlog.Printf("debug", "pod %s, rep %d, migrate in from %s",
		inst.PodID, inst.Replica.RepId, prevAddr)

	out, _ := exec.Command("pidof", "rsync-client").Output()
	pids := strings.TrimSpace(string(out))
	if len(pids) > 2 {
		hlog.Printf("info", "pod %s, rep %d, rsync-client running",
			inst.PodID, inst.Replica.RepId)
		return errors.New("waiting")
	}

	clientSecretFile := fmt.Sprintf("%s/etc/rsync/client.secrets.%s",
		inConf.Prefix, inst.Name)

	err := filerender.RenderString("{{.auth}}", clientSecretFile, 0600, map[string]interface{}{
		"auth": prevAuth,
	})
	if err != nil {
		return err
	}

	srcAddr := fmt.Sprintf("rsync://%s@%s/%s/*", inst.Name, prevAddr, inst.Name)
	args := []string{
		"-av",
		"--password-file",
		clientSecretFile,
		srcAddr,
		napi.PodVolSysDir(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId) + "/",
	}
	cmd := exec.Command(inConf.Prefix+"/bin/rsync-client", args...)
	err = cmd.Start()
	if err != nil {
		return err
	}

	podRepMigrateInPending = true
	go func(cmd *exec.Cmd, inst *napi.BoxInstance) {

		err := cmd.Wait()

		podRepMigrateMu.Lock()
		defer podRepMigrateMu.Unlock()

		if err == nil {
			sysdir := napi.VolAgentSysDir(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId)
			if _, err = os.Stat(sysdir); err == nil {
				inst.StatusActionSet(inapi.OpActionMigrated)
			}
		}

		if err == nil {
			hlog.Printf("info", "hostlet pod %s, rep %d, migrage rsync pull OK",
				inst.PodID, inst.Replica.RepId)
		} else {
			hlog.Printf("info", "hostlet pod %s, rep %d, migrage rsync pull err %v",
				inst.PodID, inst.Replica.RepId, err)
		}
		podRepMigrateInPending = false
	}(cmd, inst)

	return nil
}

func podRepMigrateOut(inst *napi.BoxInstance) error {

	if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionMigrate|inapi.OpActionStopped) {

		opt, ok := inst.Replica.Options.Get("rsync/auth")
		if !ok {
			return nil // TODO
		}

		rsyncdReload := false

		//
		kv := rsyncdActiveSecrets.Get(inst.Name)
		if kv == nil || kv.String() != opt.String() {

			rsyncdActiveSecrets.Set(inst.Name, opt.String())

			if err := filerender.RenderString(
				rsyncdSecretsTemplate,
				inConf.Prefix+"/etc/rsyncd/rsyncd.secrets",
				0600,
				map[string]interface{}{
					"items": rsyncdActiveSecrets,
				},
			); err != nil {
				hlog.Printf("warn", "rsyncd init err %s", err.Error())
				rsyncdActiveSecrets.Del(inst.Name)
				return err
			}

			rsyncdReload = true
		}

		if !rsyncdInited || rsyncdReload {

			os.MkdirAll(inConf.Prefix+"/etc/rsyncd/rsyncd.d", 0755)
			os.MkdirAll(inConf.Prefix+"/var/rsyncd", 0755)
			exec.Command("install", "/usr/bin/rsync", inConf.Prefix+"/bin/rsyncd").Output()

			sets := map[string]interface{}{
				"prefix":      inConf.Prefix,
				"server_port": fmt.Sprintf("%d", inConf.Config.Host.LanAddr.Port()+5),
			}
			rsyncdActiveModules.Set(inst.Name,
				napi.PodVolSysDir(inst.Replica.VolSysMnt, inst.PodID, inst.Replica.RepId))
			mods := []napi.RsyncModuleItem{}
			for _, v := range rsyncdActiveModules {
				mods = append(mods, napi.RsyncModuleItem{
					User: v.Key,
					Dir:  v.Value,
				})
			}
			sets["items"] = mods

			if err := filerender.RenderString(
				rsyncdConfTemplate,
				inConf.Prefix+"/etc/rsyncd/rsyncd.conf",
				0600,
				sets,
			); err != nil {
				hlog.Printf("warn", "rsyncd init err %s", err.Error())
				rsyncdActiveSecrets.Del(inst.Name)
				return err
			}
			rsyncdInited = true

			hlog.Printf("debug", "pod %s, rep %d, stopped",
				inst.PodID, inst.Replica.RepId)
		}

		if !rsyncdInited || rsyncdReload {

			out, _ := exec.Command("pidof", "rsyncd").Output()
			pids := strings.TrimSpace(string(out))
			if len(pids) > 2 {
				exec.Command("killall", "rsyncd").Output()
				time.Sleep(1e9)
			}
			os.Remove(inConf.Prefix + "/var/rsyncd/rsyncd.pid")

			hlog.Printf("debug", "pod %s, rep %d, rsyncd restart",
				inst.PodID, inst.Replica.RepId)

			_, err := exec.Command(inConf.Prefix+"/bin/rsyncd",
				"--daemon", "--config", inConf.Prefix+"/etc/rsyncd/rsyncd.conf").Output()
			if err != nil {
				rsyncdActiveSecrets.Del(inst.Name)
				return err
			}

			hlog.Printf("info", "host pod %s, rep %d, rsyncd running",
				inst.PodID, inst.Replica.RepId)
		}
	}

	return nil
}
