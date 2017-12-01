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

package config

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/connect"

	"github.com/sysinner/incore/inapi"
)

const (
	Version = "0.3.1.alpha.1"
)

type HostMember struct {
	Id        string                `json:"id"`
	ZoneId    string                `json:"zone_id,omitempty"`
	LanAddr   inapi.HostNodeAddress `json:"lan_addr"`
	WanAddr   inapi.HostNodeAddress `json:"wan_addr,omitempty"`
	HttpPort  uint16                `json:"http_port,omitempty"`
	SecretKey string                `json:"secret_key,omitempty"`
}

type ConfigCommon struct {
	filepath              string
	InstanceId            string                   `json:"instance_id"`
	Host                  HostMember               `json:"host"`
	Masters               []inapi.HostNodeAddress  `json:"masters"`
	IoConnectors          connect.MultiConnOptions `json:"io_connects"`
	PodHomeDir            string                   `json:"pod_home_dir"`
	Options               types.Labels             `json:"items,omitempty"`
	PprofHttpPort         uint16                   `json:"pprof_http_port,omitempty"`
	InpackServiceUrl      string                   `json:"inpack_service_url,omitempty"`
	IamServiceUrlFrontend string                   `json:"iam_service_url_frontend,omitempty"`
}

func (cfg *ConfigCommon) Sync() error {
	return json.EncodeToFile(cfg, cfg.filepath, "  ")
}

var (
	Prefix string
	Config ConfigCommon
	User   = &user.User{
		Uid:      "2048",
		Gid:      "2048",
		Username: "action",
		HomeDir:  "/home/action",
	}
)

func Init() error {

	var err error

	//
	if u, err := user.Current(); err != nil || u.Uid != "0" {
		return fmt.Errorf("Access Denied : must be run as root")
	}

	if Prefix, err = filepath.Abs(filepath.Dir(os.Args[0]) + "/.."); err != nil {
		Prefix = "/opt/sysinner"
	}

	//
	if err := json.DecodeFile(Prefix+"/etc/config.json", &Config); err != nil {
		return err
	}
	Config.filepath = Prefix + "/etc/config.json"

	if err := init_host(); err != nil {
		return err
	}

	if err := init_iox(); err != nil {
		return err
	}

	//
	if Config.PodHomeDir == "" {
		Config.PodHomeDir = Prefix + "/var/pods"
	}

	if Config.IamServiceUrlFrontend != "" && !strings.HasPrefix(Config.IamServiceUrlFrontend, "http") {
		return fmt.Errorf("Invalid iam_service_url_frontend")
	}

	if err := init_user(); err != nil {
		return err
	}

	return Config.Sync()
}

func init_host() error {

	if len(Config.Host.Id) < 16 {
		Config.Host.Id = idhash.RandHexString(16)
		Config.Sync()
	}

	// Private IP
	// 10.0.0.0 ~ 10.255.255.255
	// 172.16.0.0 ~ 172.31.255.255
	// 192.168.0.0 ~ 192.168.255.255
	if !Config.Host.LanAddr.Valid() {

		// auto setup local area ip address
		addrs, _ := net.InterfaceAddrs()
		reg, _ := regexp.Compile(`^(.*)\.(.*)\.(.*)\.(.*)\/(.*)$`)
		for _, addr := range addrs {

			ips := reg.FindStringSubmatch(addr.String())
			if len(ips) != 6 || (ips[1] == "127" && ips[2] == "0") {
				continue
			}

			ipa, _ := strconv.Atoi(ips[1])
			ipb, _ := strconv.Atoi(ips[2])

			if ipa == 10 ||
				(ipa == 172 && ipb >= 16 && ipb <= 31) ||
				(ipa == 192 && ipb == 168) {
				Config.Host.LanAddr.SetIP(
					fmt.Sprintf("%s.%s.%s.%s", ips[1], ips[2], ips[3], ips[4]),
				)
				break
			}
		}

		if len(Config.Host.LanAddr) < 8 {
			Config.Host.LanAddr.SetIP("127.0.0.1")
		}
	}

	if Config.Host.LanAddr.Port() < 1024 {
		Config.Host.LanAddr.SetPort(9529)
	}

	if Config.Host.HttpPort < 1024 {
		Config.Host.HttpPort = 9530
	}

	if len(Config.Host.SecretKey) < 32 {
		Config.Host.SecretKey = idhash.RandBase64String(32)
		Config.Sync()
	}

	return nil
}

//
func init_iox() error {

	io_name := types.NewNameIdentifier("in_local_cache")
	opts := Config.IoConnectors.Options(io_name)

	if opts == nil {

		opts = &connect.ConnOptions{
			Name:      io_name,
			Connector: "iomix/skv/Connector",
			Driver:    types.NewNameIdentifier("lynkdb/kvgo"),
		}
	}

	if opts.Value("data_dir") == "" {
		opts.SetValue("data_dir", Prefix+"/var/"+string(io_name))
	}

	Config.IoConnectors.SetOptions(*opts)

	return nil
}

func init_user() error {

	if _, err := user.Lookup(User.Username); err != nil {

		nologin, err := exec.LookPath("nologin")
		if err != nil {
			nologin = "/sbin/nologin"
		}

		if _, err = exec.Command(
			"/usr/sbin/useradd",
			"-d", User.HomeDir,
			"-s", nologin,
			"-u", User.Uid, User.Username,
		).Output(); err != nil {
			return err
		}
	}

	// if _, err := exec.Command(
	// 	"/usr/sbin/usermod",
	// 	"-a",
	// 	"-G",
	// 	User.Username,
	// 	"nginx",
	// ).Output(); err != nil {
	// 	return err
	// }

	return nil
}
