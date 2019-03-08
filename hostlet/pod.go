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

package hostlet

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"

	inCfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
)

var (
	podRepCtrlNumMax = 200
	binInstall       = "install"
)

func podRepCtrlSet(pod *inapi.PodRep) error {

	prev := nstatus.PodRepActives.Get(pod.RepKey())

	if prev != nil {

		if prev.Operate.Version == pod.Operate.Version &&
			inapi.OpActionAllow(pod.Replica.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) &&
			inapi.OpActionAllow(prev.Replica.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			return nil
		}

		if prev.Operate.Version < pod.Operate.Version {
			nstatus.PodRepActives.Del(prev.RepKey())
			prev = nil
		}
	}

	sysdir := napi.VolAgentSysDir(pod.Meta.ID, pod.Replica.RepId)

	if prev == nil {

		if len(nstatus.PodRepActives) > podRepCtrlNumMax {
			return errors.New("no available host resources in this moment")
		}

		if _, err := os.Stat(sysdir); os.IsNotExist(err) {
			if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
				hlog.Printf("error", "hostlet/pod-pull %s %s", pod.Meta.ID, err.Error())
				return err
			}
		}

		prev = pod

		nstatus.PodRepActives.Set(prev)

	} else if pod.Operate.Version > prev.Operate.Version ||
		(pod.Meta.Updated > 1 && pod.Meta.Updated != prev.Meta.Updated) ||
		(pod.Replica.Updated > 1 && pod.Replica.Updated != prev.Replica.Updated) {

		prev.Meta.Updated = pod.Meta.Updated
		prev.Spec = pod.Spec
		prev.Replica = pod.Replica
		prev.Operate = pod.Operate

		// hlog.Printf("error", "hostlet/pod-pull %s action %d", pod.Operate.Action)

		// TODO destroy bound apps
		if pod.Apps != nil {

			if prev.Apps == nil {
				prev.Apps = pod.Apps
			} else {

				for _, a := range pod.Apps {
					prev.Apps.Sync(a)
				}
			}
		}

	} else {
		return nil
	}

	if _, err := os.Stat(sysdir); os.IsNotExist(err) {
		if err := inutils.FsMakeDir(sysdir, 2048, 2048, 0750); err != nil {
			hlog.Printf("error", "hostlet/pod-pull %s %s", prev.Meta.ID, err.Error())
			return err
		}
	}

	if err := json.EncodeToFile(prev, sysdir+"/pod_instance.json", "  "); err != nil {
		hlog.Printf("error", "hostlet/pod-pull %s %s", prev.Meta.ID, err.Error())
		return err
	}

	return nil
}

func podRepListCtrlRefresh() error {

	defer func() {
		if r := recover(); r != nil {
			hlog.Printf("error", "host/rep-control-refresh panic %v", r)
		}
	}()

	var (
		tn      = uint32(time.Now().Unix())
		ctrDels = []string{}
		boxDels = []string{}
	)

	for _, pod := range nstatus.PodRepActives {

		if inapi.OpActionAllow(pod.Replica.Action, inapi.OpActionDestroy|inapi.OpActionDestroyed) {
			continue
		}

		var (
			instName   = napi.BoxInstanceName(pod.Meta.ID, pod.Replica.RepId)
			instAction = boxActionRefreshEntry(instName, pod, pod.Spec.Box)
		)

		hlog.Printf("debug", "hostlet pod %s:%d, opAction %s, status %s, removes %s",
			instAction.PodID, instAction.Replica.RepId,
			strings.Join(inapi.OpActionStrings(instAction.Replica.Action), ","),
			strings.Join(inapi.OpActionStrings(instAction.Status.Action), ","),
			strings.Join(nstatus.PodRepRemoves, ","),
		)

		if nstatus.PodRepRemoves.Has(instAction.Name) {

			if ev := nstatus.BoxActives.Get(instAction.Name); ev != nil {
				boxDels = append(boxDels, instAction.Name)
			}

			if ev := nstatus.PodRepActives.Get(pod.RepKey()); ev != nil {
				ctrDels = append(ctrDels, pod.RepKey())
			}

			continue
		}

		drv := boxDrivers.Get(instAction.Spec.Image.Driver)
		if drv == nil {
			hlog.Printf("info", "hostlet rep %s:%d, driver %s not setup",
				instAction.PodID, instAction.Replica.RepId, instAction.Spec.Image.Driver)
			continue
		}

		if (instAction.UpUpdated+60) < tn && instAction.Replica.Action == 0 {

			hlog.Printf("debug", "hostlet rep %s:%d, timeout with control",
				instAction.PodID, instAction.Replica.RepId)

			instAction.Replica.Action = inapi.OpActionDestroy

			if inapi.OpActionAllow(instAction.Status.Action, inapi.OpActionDestroyed) {
				// nstatus.BoxActives.Del(instAction.Name)
				continue
			}
		}

		hlog.Printf("debug", "hostlet rep %s:%d, opAction %s",
			instAction.PodID, instAction.Replica.RepId,
			strings.Join(inapi.OpActionStrings(instAction.Replica.Action), ","),
		)

		if inapi.OpActionAllow(instAction.Replica.Action, inapi.OpActionMigrate) &&
			!inapi.OpActionAllow(instAction.Replica.Action, inapi.OpActionDestroy) {

			/**
			hlog.Printf("info", "pod %s, rep %d, action %s",
				instAction.PodID, instAction.Replica.RepId,
				strings.Join(inapi.OpActionStrings(instAction.Replica.Action), ","),
			)
			*/

			if podRepMigrate(instAction) {
				continue
			}
		}

		if inapi.OpActionAllow(instAction.Replica.Action, inapi.OpActionStart) {
			instAction.Status.Action = inapi.OpActionStatusClean(
				instAction.Replica.Action, instAction.Status.Action)
		}

		if nstatus.BoxActives.OpLockNum() > 10 {
			continue
		}

		go func(drv napi.BoxDriver, inst *napi.BoxInstance) {

			if !inst.OpLock() {
				return
			}

			defer func(inst *napi.BoxInstance) {
				if r := recover(); r != nil {
					hlog.Printf("error", "host/driver panic %v", r)
				}
				inst.OpUnlock()
			}(inst)

			var err error

			if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionDestroy) {
				err = drv.BoxRemove(inst)
			} else if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStop) {
				err = drv.BoxStop(inst)
			} else if inapi.OpActionAllow(inst.Replica.Action, inapi.OpActionStart) {
				if err = podRepVolSetup(inst); err == nil {
					err = drv.BoxStart(inst)
				}
			}

			logType, logMsg := inapi.PbOpLogOK, fmt.Sprintf("box %s, Setup OK", inst.Name)
			if err != nil {
				logType = inapi.PbOpLogError
				logMsg = fmt.Sprintf("box %s, Setup ERR %s", inst.Name, err.Error())
			}

			nstatus.PodRepOpLogs.LogSet(
				inst.OpRepKey(), inst.PodOpVersion,
				napi.NsOpLogHostletRepAction, logType, logMsg,
			)

		}(drv, instAction)
	}

	for _, repKey := range ctrDels {
		nstatus.PodRepActives.Del(repKey)
		hlog.Printf("info", "hostlet/box rep %s, control unbound", repKey)
	}

	for _, instName := range boxDels {
		nstatus.BoxActives.Del(instName)
		hlog.Printf("debug", "hostlet/box %s, status unbound", instName)
	}
	if len(boxDels) > 0 {
		ConfigFlush()
	}

	return nil
}

func podRepVolSetup(inst *napi.BoxInstance) error {

	if inapi.OpActionAllow(inst.Status.Action, inapi.OpActionRunning) {
		return nil
	}

	tn := time.Now().Unix()
	if inst.SysVolSynced+86400 > tn {
		return nil
	}

	var (
		dirOpt     = napi.VolPodPath(inst.PodID, inst.Replica.RepId, "/opt")
		dirPodHome = napi.VolPodHomeDir(inst.PodID, inst.Replica.RepId)
		initSrc    = inCfg.Prefix + "/bin/ininit"
		initDst    = dirPodHome + "/.sysinner/ininit"
		agentSrc   = inCfg.Prefix + "/bin/inagent"
		agentDst   = dirPodHome + "/.sysinner/inagent"
		bashrcSrc  = inCfg.Prefix + "/misc/bash/bashrc"
		bashrcDst  = dirPodHome + "/.bashrc"
		bashpfSrc  = inCfg.Prefix + "/misc/bash/bash_profile"
		bashpfDst  = dirPodHome + "/.bash_profile"
	)

	if err := inutils.FsMakeDir(dirOpt, 2048, 2048, 0750); err != nil {
		return fmt.Errorf("hostlet/box BOX:%s, FsMakeDir Err: %s", inst.Name, err.Error())
	}

	if err := inutils.FsMakeDir(dirPodHome+"/.sysinner", 2048, 2048, 0750); err != nil {
		return fmt.Errorf("hostlet/box BOX:%s, FsMakeDir Err: %s", inst.Name, err.Error())
	}

	//
	exec.Command(binInstall, "-m", "755", "-g", "root", "-o", "root", initSrc, initDst).Output()
	exec.Command(binInstall, "-m", "755", "-g", "root", "-o", "root", agentSrc, agentDst).Output()
	exec.Command("rsync", bashrcSrc, bashrcDst).Output()
	exec.Command("rsync", bashpfSrc, bashpfDst).Output()

	inst.SysVolSynced = tn

	hlog.Printf("info", "host/box %s, start/pre setup", inst.Name)

	return nil
}
