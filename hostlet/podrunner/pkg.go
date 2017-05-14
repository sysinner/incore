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

package podrunner

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/lessos/lessgo/logger"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"code.hooto.com/lessos/loscore/config"
	"code.hooto.com/lessos/loscore/losapi"
	"code.hooto.com/lessos/loscore/losutils"
	"code.hooto.com/lessos/lospack/lpapi"
)

var (
	cmd_shasum = "/usr/bin/sha256sum"
	cmd_tar    = "/bin/tar"
	cmd_chown  = "/usr/bin/chown"
	lpm_sets   types.ArrayString
	lpm_mu     sync.Mutex
)

func init() {

	if path, err := exec.LookPath("sha256sum"); err == nil {
		cmd_shasum = path
	}

	if path, err := exec.LookPath("tar"); err == nil {
		cmd_tar = path
	}

	if path, err := exec.LookPath("chown"); err == nil {
		cmd_chown = path
	}
}

func lpm_mountpath(name, version string) string {
	return fmt.Sprintf("/usr/los/%s/%s", name, version)
}

func lpm_filename(name, version, release, os, arch string) string {
	return fmt.Sprintf("%s-%s-%s.%s.%s.txz", name, version, release, os, arch)
}

func lpm_hostpath(name, version, release, os, arch string) string {
	return fmt.Sprintf("/opt/los/lpm/.cache/%s/%s/%s", name, version,
		lpm_filename(name, version, release, os, arch))
}

func lpm_hostdir(name, version, release, os, arch string) string {
	return fmt.Sprintf("/opt/los/lpm/%s/%s/%s.%s.%s", name, version, release, os, arch)
}

func lpm_prepare(inst *BoxInstance) error {

	for _, app := range inst.Apps {

		for _, p := range app.Spec.Packages {

			if err := lpm_entry_sync(p); err != nil {
				return err
			}
		}
	}

	return nil
}

func lpm_entry_sync(vp losapi.VolumePackage) error {

	if vp.Name == "" || len(vp.Version) < 1 || len(vp.Release) < 1 {
		return errors.New("Package Not Found")
	}

	tag_name := vp.Name + "." + string(vp.Version)

	lpm_mu.Lock()
	if lpm_sets.Contain(tag_name) {
		lpm_mu.Unlock()
		// logger.Printf("info", "nodelet/Package Sync %s Command Skip", vp.Name)
		return nil
	}
	lpm_sets.Insert(tag_name)
	lpm_mu.Unlock()

	defer func(tag_name string) {
		lpm_mu.Lock()
		lpm_sets.Remove(tag_name)
		lpm_mu.Unlock()
	}(tag_name)

	phostdir := lpm_hostdir(vp.Name, vp.Version, vp.Release, vp.Dist, vp.Arch)
	if _, err := os.Stat(phostdir + "/.lospack/lospack.json"); err == nil {
		return nil
	}

	// TODO
	url := fmt.Sprintf("%s/lps/v1/pkg/entry?name=%s&version=%s&release=%s&dist=%s&arch=%s",
		config.Config.LpsServiceUrl,
		vp.Name, vp.Version, vp.Release, vp.Dist, vp.Arch)
	c := httpclient.Get(url)
	defer c.Close()

	var pkg lpapi.Package
	if err := c.ReplyJson(&pkg); err != nil {
		logger.Printf("error", "nodelet/Package Sync %s", url)
		return err
	}

	if pkg.Kind != "Package" {
		return errors.New("Package Not Found: " + url)
	}

	var (
		pfilename = lpm_filename(pkg.Meta.Name, string(pkg.Version), string(pkg.Release), pkg.PkgOS, pkg.PkgArch)
		pfilepath = lpm_hostpath(pkg.Meta.Name, string(pkg.Version), string(pkg.Release), pkg.PkgOS, pkg.PkgArch)
	)

	losutils.FsMakeDir(phostdir, 2048, 2048, 0750)

	if _, err := os.Stat(pfilepath); err == nil {

		if lpm_entry_sync_sumcheck(pfilepath) == pkg.PkgSum {
			return lpm_entry_sync_extract(pfilepath, phostdir)
		}
	}
	losutils.FsMakeFileDir(pfilepath, 2048, 2048, 0750)

	tmpfile := pfilepath + ".tmp"
	fp, err := os.Create(tmpfile)
	if err != nil {
		logger.Printf("error", "Create Package `%s` Failed", pfilepath)
		return err
	}
	defer fp.Close()

	dlurl := fmt.Sprintf("%s/lps/v1/pkg/dl/%s/%s/%s",
		config.Config.LpsServiceUrl, pkg.Meta.Name, pkg.Version, pfilename)

	// logger.Printf("info", "Download Package From (%s)", dlurl)
	rsp, err := http.Get(dlurl)
	if err != nil {
		logger.Printf("error", "Download Package `%s` Failed", dlurl)
		return err
	}
	defer rsp.Body.Close()

	if n, err := io.Copy(fp, rsp.Body); n < 1 || err != nil {
		logger.Printf("error", "Download Package `%s` Failed", dlurl)
		return errors.New("Download Package Failed")
	}

	if lpm_entry_sync_sumcheck(tmpfile) != pkg.PkgSum {
		logger.Printf("error", "SumCheck Error (%s)", tmpfile)
		return errors.New("Download Package Failed")
	}

	if err := os.Rename(tmpfile, pfilepath); err != nil {
		return err
	}
	os.Chown(pfilepath, 2048, 2048)

	if err := lpm_entry_sync_extract(pfilepath, phostdir); err != nil {
		return err
	}

	// if pv, ok := pkg.Options.Get("p6/lpm/install-prefix"); ok && len(pv.String()) > 5 {

	// 	exec.Command("mkdir", "-p", pv.String()).Output()

	// 	if _, err := exec.Command("rsync", "-av", phostdir+"/*", pv.String()).Output(); err != nil {
	// 		return nil
	// 	}
	// }

	return nil
}

func lpm_entry_sync_sumcheck(filepath string) string {

	rs, err := exec.Command(cmd_shasum, filepath).Output()
	if err != nil {
		logger.Printf("error", "SumCheck Error %s", err.Error())
		return ""
	}

	rss := strings.Split(string(rs), " ")
	if len(rss) < 2 {
		return ""
	}

	return "sha256:" + rss[0]
}

func lpm_entry_sync_extract(file, dest string) error {

	if _, err := exec.Command(cmd_tar, "-Jxvf", file, "-C", dest).Output(); err != nil {
		logger.Printf("error", "Package Extract to `%s` Failed: %s", dest, err.Error())
		return err
	}

	exec.Command(cmd_chown, "-R", "action:action", dest).Output()

	return nil
}
