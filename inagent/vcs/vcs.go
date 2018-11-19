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

package vcs

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hini4g/hini"
	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/inagent/agtapi"
	"github.com/sysinner/incore/inagent/status"
	"github.com/sysinner/incore/inapi"
)

var (
	cmd_git   = "git"
	home_dir  = "/home/action"
	vcs_mu    sync.Mutex
	vcsActive *vcsActiveItem
)

const (
	VcsActionInit    uint32 = 1 << 16
	VcsActionPullOK  uint32 = 1 << 19
	VcsActionPullER  uint32 = 1 << 20
	vcsOnUpdateRange uint32 = 600
)

type vcsActiveItem struct {
	dir    string
	Cmd    *exec.Cmd
	outbuf *bytes.Buffer
	errbuf *bytes.Buffer
	output string
}

func (it *vcsActiveItem) Output() string {
	it.output += it.outbuf.String()
	it.output += it.errbuf.String()
	return it.output
}

func oplog_name(dir string) string {
	return "pod/vcs/" + strings.Replace(dir, "/", "_", -1)
}

func targetDir(dir string) string {
	return filepath.Clean(home_dir + "/" + dir)
}

func actionLogStatus(act uint32) string {
	if inapi.OpActionAllow(act, inapi.VcsActionOK) {
		return inapi.PbOpLogOK
	} else if inapi.OpActionAllow(act, inapi.VcsActionUnAuth) {
		return inapi.PbOpLogError
	} else if inapi.OpActionAllow(act, inapi.VcsActionER) {
		return inapi.PbOpLogError
	}
	return inapi.PbOpLogInfo
}

func Action(pod *inapi.Pod) (int, error) {

	if pod.Apps == nil || len(pod.Apps) < 1 {
		return 0, nil
	}

	var (
		repos types.ArrayString
	)

	for _, app := range pod.Apps {
		for _, p := range app.Spec.VcsRepos {
			repos.Set(p.Dir)
			status.VcsRepos.Set(p)

			vcsStatus := status.VcsStatuses.Get(p.Dir)
			if vcsStatus == nil {
				vcsStatus = &agtapi.VcsStatusItem{
					Dir:       p.Dir,
					AppSpecId: app.Spec.Meta.ID,
				}
				status.VcsStatuses.Set(vcsStatus)
			}
		}
	}

	for _, v := range status.VcsRepos {
		if !repos.Has(v.Dir) {
			status.VcsRepos.Del(v.Dir)
		}
	}

	n := len(status.VcsRepos)

	for _, v := range status.VcsRepos {

		//
		vcsAction(v)

		vcsStatus := status.VcsStatuses.Get(v.Dir)

		hlog.Printf("debug", "%s : %d : %s", v.Dir, vcsStatus.Action, vcsStatus.Msg)

		status.OpLog.LogSet(
			pod.Operate.Version,
			oplog_name(v.Dir),
			actionLogStatus(vcsStatus.Action),
			vcsStatus.Msg)

		if inapi.OpActionAllow(vcsStatus.Action, inapi.VcsActionOK) {
			n -= 1
		}
	}

	return n, nil
}

func vcsAction(vit *inapi.VcsRepoItem) {

	if vit.Plan != "on_boot" && vit.Plan != "on_update" {
		return
	}

	vcsStatus := status.VcsStatuses.Get(vit.Dir)
	if vcsStatus == nil {
		return
	}

	vcs_mu.Lock()
	defer vcs_mu.Unlock()

	if vit.Plan == "on_boot" {
		if inapi.OpActionAllow(vcsStatus.Action, inapi.VcsActionOK) {
			return
		}
	}

	var (
		tn = uint32(time.Now().Unix())
	)

	if inapi.OpActionAllow(vcsStatus.Action, inapi.VcsActionOK) {
		if tn > vcsStatus.Updated && tn-vcsStatus.Updated < vcsOnUpdateRange {
			return
		}
	}

	if vcsActive != nil && vcsActive.dir != vit.Dir {
		return
	}

	if vcsActive == nil {
		if err := vcsGitPrepare(vit); err != nil {
			vcsStatus.Action = inapi.VcsActionER
			vcsStatus.Msg = "Vcs Prepare Err " + err.Error()
			hlog.Printf("error", vcsStatus.Msg)
			return
		}
	}

	//
	act, msg := vcsGitFetch(vit)
	if !inapi.OpActionAllow(act, VcsActionPullOK) {

		if act == 0 {
			vcsStatus.Action = inapi.VcsActionPull
			msg = "git pull pending"
		} else if inapi.OpActionAllow(act, inapi.VcsActionUnAuth) {
			vcsStatus.Action = inapi.VcsActionUnAuth
			msg = "git Authentication failed"
		} else if inapi.OpActionAllow(act, VcsActionPullER) {
			vcsStatus.Action = inapi.VcsActionER
		}

		vcsStatus.Msg = msg

		return
	}

	if ver, err := vcsGitCheckoutAndMerge(vit); err == nil {
		vcsStatus.Action = inapi.VcsActionOK
		vcsStatus.Version = ver
		vcsStatus.Updated = tn
		vcsStatus.Msg = "Git Commit " + ver[:12]
	} else {
		vcsStatus.Action = inapi.VcsActionER
		vcsStatus.Msg = "error to checkout branch " + vit.Branch
		if err != nil {
			vcsStatus.Msg += ", err " + err.Error()
		}
	}
}

func vcsGitPrepare(vit *inapi.VcsRepoItem) error {

	var (
		tdir     = targetDir(vit.Dir)
		conf     = tdir + "/.git/config"
		cfp, err = os.Open(conf)
		url      = vit.Url
	)

	if err != nil {

		if !os.IsNotExist(err) {
			return err
		}

		if err = os.MkdirAll(tdir, 0755); err != nil {
			return err
		}

		if _, err = exec.Command(cmd_git, "init", tdir).Output(); err != nil {
			return err
		}

		cfp, err = os.Open(conf)
		if err != nil {
			return err
		}
	}
	defer cfp.Close()

	bs, err := ioutil.ReadAll(cfp)
	if err != nil {
		return err
	}
	opts, err := hini.ParseString(string(bs))
	if err != nil {
		return err
	}

	if vit.AuthUser != "" && vit.AuthPass != "" {
		if strings.HasPrefix(url, "http://") {
			url = strings.Replace(url, "http://", "http://"+vit.AuthUser+":"+vit.AuthPass+"@", 1)
		} else if strings.HasPrefix(url, "https://") {
			url = strings.Replace(url, "https://", "https://"+vit.AuthUser+":"+vit.AuthPass+"@", 1)
		}
	}

	local_url, ok := opts.ValueOK("remote/origin/url")
	if !ok {
		args := []string{
			"--git-dir=" + tdir + "/.git",
			"remote",
			"add",
			"origin",
			url,
		}
		if _, err = exec.Command(cmd_git, args...).Output(); err != nil {
			return err
		}

		opts, err = hini.ParseFile(conf)
		if err != nil {
			return err
		}
		local_url, ok = opts.ValueOK("remote/origin/url")
		if !ok {
			return errors.New("git remote set-url fail")
		}
	}

	if local_url.String() != url {
		args := []string{
			"--git-dir=" + tdir + "/.git",
			"remote",
			"set-url",
			"origin",
			url,
		}
		if _, err = exec.Command(cmd_git, args...).Output(); err != nil {
			return err
		}
	}

	return nil
}

func vcsGitFetch(vit *inapi.VcsRepoItem) (act uint32, msg string) {

	if vcsActive != nil {

		if vcsActive.dir != vit.Dir {
			return 0, ""
		}

		if vcsActive.Cmd.Process != nil {
			if vcsActive.Cmd.ProcessState == nil {
				// pending
			}
		}

		if vcsActive.Cmd.ProcessState != nil && vcsActive.Cmd.ProcessState.Exited() {

			if vcsActive.Cmd.ProcessState.Success() {
				act = VcsActionPullOK
			} else {
				if strings.Contains(vcsActive.Output(), "could not read Username") {
					act = inapi.VcsActionUnAuth
					msg = "VcsRepo Auth Fail"
				} else {
					act = VcsActionPullER
					msg = "unknown error " + vcsActive.Cmd.ProcessState.String()
				}
			}

			if vcsActive.Cmd.Process != nil {
				vcsActive.Cmd.Process.Kill()
				time.Sleep(5e8)
			}

			vcsActive = nil
		}

		return
	}

	//
	tdir := targetDir(vit.Dir)
	args := []string{
		"--git-dir=" + tdir + "/.git",
		"fetch",
		"origin",
		vit.Branch,
	}
	os.Setenv("GIT_TERMINAL_PROMPT", "0")
	cmd := exec.Command(cmd_git, args...)

	item := &vcsActiveItem{
		dir:    vit.Dir,
		Cmd:    cmd,
		errbuf: &bytes.Buffer{},
		outbuf: &bytes.Buffer{},
	}

	cmd.Stderr = item.errbuf
	cmd.Stdout = item.outbuf

	if err := cmd.Start(); err != nil {
		act = VcsActionPullER
		msg = "VcsRepo Pull Fail " + err.Error()
	} else {
		vcsActive = item
		go cmd.Wait()
	}

	return
}

func vcsGitCheckoutAndMerge(vit *inapi.VcsRepoItem) (string, error) {

	//
	tdir := targetDir(vit.Dir)
	args := []string{
		"--git-dir=" + tdir + "/.git",
		"checkout",
		vit.Branch,
	}
	cmd := exec.Command(cmd_git, args...)
	cmd.Dir = tdir
	if _, err := cmd.Output(); err != nil {
		return "", errors.New("failed to checkout branch " + err.Error())
	}

	//
	args = []string{
		"--git-dir=" + tdir + "/.git",
		"merge",
		vit.Branch,
		"FETCH_HEAD",
	}
	cmd = exec.Command(cmd_git, args...)
	cmd.Dir = tdir
	if _, err := cmd.Output(); err != nil {
		return "", errors.New("failed to merge branch " + err.Error())
	}

	//
	args = []string{
		"--git-dir=" + tdir + "/.git",
		"log",
		"--format=%H",
		"-n",
		"1",
	}
	out, err := exec.Command(cmd_git, args...).Output()
	if err != nil {
		return "", errors.New("failed to get last log id " + err.Error())
	}

	ver := strings.TrimSpace(string(out))
	if inapi.VcsGitVerReg.MatchString(ver) {
		return ver, nil
	}

	return "", errors.New("fail to get last log id")
}
