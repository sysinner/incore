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

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/net/httpclient"
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
	"github.com/sysinner/inpack/ipapi"
)

var (
	cmd_shasum = "/usr/bin/sha256sum"
	cmd_tar    = "/bin/tar"
	cmd_chown  = "/usr/bin/chown"
	ipm_sets   types.ArrayString
	ipm_mu     sync.Mutex
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

func ipm_mountpath(name, version string) string {
	return fmt.Sprintf("/usr/sysinner/%s/%s", name, version)
}

func ipm_filename(pkg ipapi.Package) string {
	return ipapi.PackageFilename(pkg.Meta.Name, pkg.Version) + ".txz"
}

func ipm_hostpath(pkg ipapi.Package) string {
	return fmt.Sprintf("/opt/sysinner/ipm/.cache/%s/%s/%s",
		pkg.Meta.Name, string(pkg.Version.Version), ipm_filename(pkg))
}

func ipm_hostdir(name, version, release, dist, arch string) string {
	return fmt.Sprintf("/opt/sysinner/ipm/%s/%s/%s.%s.%s", name, version, release, dist, arch)
}

func ipm_prepare(inst *BoxInstance) error {

	for _, app := range inst.Apps {

		for _, p := range app.Spec.Packages {

			if err := ipm_entry_sync(p); err != nil {
				return err
			}
		}
	}

	return nil
}

func ipm_entry_sync(vp inapi.VolumePackage) error {

	if vp.Name == "" || len(vp.Version) < 1 || len(vp.Release) < 1 {
		return errors.New("Package Not Found")
	}

	tag_name := vp.Name + "." + string(vp.Version)

	ipm_mu.Lock()
	if ipm_sets.Contain(tag_name) {
		ipm_mu.Unlock()
		// hlog.Printf("info", "nodelet/Package Sync %s Command Skip", vp.Name)
		return nil
	}
	ipm_sets.Insert(tag_name)
	ipm_mu.Unlock()

	defer func(tag_name string) {
		ipm_mu.Lock()
		ipm_sets.Remove(tag_name)
		ipm_mu.Unlock()
	}(tag_name)

	phostdir := ipm_hostdir(vp.Name, vp.Version, vp.Release, vp.Dist, vp.Arch)
	if _, err := os.Stat(phostdir + "/.inpack/inpack.json"); err == nil {
		return nil
	}

	// TODO
	url := fmt.Sprintf("%s/ips/v1/pkg/entry?name=%s&version=%s&release=%s&dist=%s&arch=%s",
		config.Config.InpackServiceUrl,
		vp.Name, vp.Version, vp.Release, vp.Dist, vp.Arch)
	c := httpclient.Get(url)
	defer c.Close()

	var pkg struct {
		types.TypeMeta
		ipapi.Package
	}
	if err := c.ReplyJson(&pkg); err != nil {
		hlog.Printf("error", "nodelet/Package Sync %s", url)
		return err
	}

	if pkg.Kind != "Package" {
		return errors.New("Package Not Found: " + url)
	}

	var (
		pfilename = ipm_filename(pkg.Package)
		pfilepath = ipm_hostpath(pkg.Package)
	)

	inutils.FsMakeDir(phostdir, 2048, 2048, 0750)

	if _, err := os.Stat(pfilepath); err == nil {

		if ipm_entry_sync_sumcheck(pfilepath) == pkg.SumCheck {
			return ipm_entry_sync_extract(pfilepath, phostdir)
		}
	}
	inutils.FsMakeFileDir(pfilepath, 2048, 2048, 0750)

	tmpfile := pfilepath + ".tmp"
	fp, err := os.Create(tmpfile)
	if err != nil {
		hlog.Printf("error", "Create Package `%s` Failed", pfilepath)
		return err
	}
	defer fp.Close()

	dlurl := fmt.Sprintf("%s/ips/v1/pkg/dl/%s/%s/%s",
		config.Config.InpackServiceUrl, pkg.Meta.Name, pkg.Version.Version, pfilename)

	hlog.Printf("info", "Download Package From (%s)", dlurl)
	rsp, err := http.Get(dlurl)
	if err != nil {
		hlog.Printf("error", "Download Package `%s` Failed", dlurl)
		return err
	}
	defer rsp.Body.Close()

	if n, err := io.Copy(fp, rsp.Body); n < 1 || err != nil {
		hlog.Printf("error", "Download Package `%s` Failed", dlurl)
		return errors.New("Download Package Failed")
	}

	if ipm_entry_sync_sumcheck(tmpfile) != pkg.SumCheck {
		hlog.Printf("error", "SumCheck Error (%s)", tmpfile)
		return errors.New("Download Package Failed")
	}

	if err := os.Rename(tmpfile, pfilepath); err != nil {
		return err
	}
	os.Chown(pfilepath, 2048, 2048)

	if err := ipm_entry_sync_extract(pfilepath, phostdir); err != nil {
		return err
	}

	// if pv, ok := pkg.Options.Get("p6/ipm/install-prefix"); ok && len(pv.String()) > 5 {

	// 	exec.Command("mkdir", "-p", pv.String()).Output()

	// 	if _, err := exec.Command("rsync", "-av", phostdir+"/*", pv.String()).Output(); err != nil {
	// 		return nil
	// 	}
	// }

	return nil
}

func ipm_entry_sync_sumcheck(filepath string) string {

	rs, err := exec.Command(cmd_shasum, filepath).Output()
	if err != nil {
		hlog.Printf("error", "SumCheck Error %s", err.Error())
		return ""
	}

	rss := strings.Split(string(rs), " ")
	if len(rss) < 2 {
		return ""
	}

	return "sha256:" + rss[0]
}

func ipm_entry_sync_extract(file, dest string) error {

	if _, err := exec.Command(cmd_tar, "-Jxvf", file, "-C", dest).Output(); err != nil {
		hlog.Printf("error", "Package Extract to `%s` Failed: %s", dest, err.Error())
		return err
	}

	exec.Command(cmd_chown, "-R", "action:action", dest).Output()

	return nil
}
