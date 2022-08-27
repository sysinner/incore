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

package inutils

import (
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

const (
	DistGen = "gen"
	ArchAll = "noarch"
)

var (
	// TODO docker -v: Docker version 17.03.0-ce, build 60ccb22
	dockerVersionReg = regexp.MustCompile("Server version:(.*)\n")
)

type EnvOs struct {
	Kernel string
}

type EnvDocker struct {
	ServerVersion string
}

func ResSysHostEnvDistArch() (string, string, error) {

	if runtime.GOOS == "darwin" {
		return runtime.GOOS, runtime.GOARCH, nil
	}

	if runtime.GOOS != "linux" {
		return "", "", errors.New("unsupported operating system")
	}

	cmd, err := exec.LookPath("lsb_release")
	if err != nil {
		return "", "", err
	}

	rs, err := exec.Command(cmd, "-r", "-i", "-s").Output()
	if err != nil {
		return "", "", err
	}

	dist := ""
	arch := runtime.GOARCH

	out := strings.Replace(string(rs), "\n", " ", -1)
	rs2 := strings.Split(out, " ")
	if len(rs2) < 2 {
		return dist, arch, errors.New("Unknow ENV")
	}
	ver := strings.Split(rs2[1], ".")

	switch rs2[0] {

	case "Rocky", "CentOS":
		dist = "el"
		if len(ver) >= 1 {
			dist += ver[0]
		}

	case "Debian":
		dist = "debian"
		if len(ver) >= 1 {
			dist += ver[0]
		}

	case "Ubuntu":
		dist = "ubuntu"
		if len(ver) >= 2 {
			dist += strings.Join(ver[:2], "")
		}

	default:
		return dist, arch, errors.New("Unknow ENV")
	}

	if arch != "amd64" {
		return dist, arch, errors.New("Unknow ENV")
	}

	return dist, arch, nil
}

func ResSysHostEnvOsInfo() EnvOs {

	var info EnvOs

	rs, err := exec.Command("uname", "-r").Output()
	if err == nil {
		info.Kernel = strings.TrimSpace(string(rs))
	}

	return info
}

func ResSyncHostEnvDockerInfo() EnvDocker {

	var info EnvDocker

	cmd, err := exec.LookPath("docker")
	if err != nil {
		return info
	}

	rs, err := exec.Command(cmd, "version").Output()
	if err == nil {
		vs := dockerVersionReg.FindStringSubmatch(string(rs))
		if len(vs) == 2 {
			info.ServerVersion = strings.TrimSpace(vs[1])
		}
	}

	return info
}
