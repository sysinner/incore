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

type HostMember struct {
	Id        string                `json:"id"`
	ZoneId    string                `json:"zone_id"`
	CellId    string                `json:"cell_id,omitempty"`
	LanAddr   inapi.HostNodeAddress `json:"lan_addr"`
	WanAddr   inapi.HostNodeAddress `json:"wan_addr"`
	HttpPort  uint16                `json:"http_port"`
	SecretKey string                `json:"secret_key"`
}

type ZoneMaster struct {
	MultiZoneEnable    bool `json:"multi_zone_enable,omitempty"`
	MultiCellEnable    bool `json:"multi_cell_enable"`
	MultiHostEnable    bool `json:"multi_host_enable"`
	MultiReplicaEnable bool `json:"multi_replica_enable"`
}

type ConfigCommon struct {
	filepath                  string                   `json:"-"`
	InstanceId                string                   `json:"instance_id"`
	Host                      HostMember               `json:"host"`
	Masters                   inapi.HostNodeAddresses  `json:"masters"`
	ZoneMaster                ZoneMaster               `json:"zone_master,omitempty"`
	ZoneMasterSchedulerPlugin string                   `json:"zone_master_scheduler_plugin,omitempty"`
	IoConnectors              connect.MultiConnOptions `json:"io_connects"`
	PodHomeDir                string                   `json:"pod_home_dir"`
	Options                   types.Labels             `json:"items,omitempty"`
	PprofHttpPort             uint16                   `json:"pprof_http_port,omitempty"`
	InpackServiceUrl          string                   `json:"inpack_service_url,omitempty"`
	IamServiceUrlFrontend     string                   `json:"iam_service_url_frontend,omitempty"`
	IamServiceUrlGlobal       string                   `json:"iam_service_url_global,omitempty"`
	LxcFsEnable               bool                     `json:"lxc_fs_enable"`
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
	InitZoneId = "local"
	InitCellId = "general"
)

func Setup() error {

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

	if err := setupHost(); err != nil {
		return err
	}

	//
	if Config.PodHomeDir == "" {
		if strings.HasPrefix(Prefix, "/opt/sysinner/in") {
			os.MkdirAll("/opt/sysinner/pods", 0755)
			Config.PodHomeDir = "/opt/sysinner/pods"
		} else {
			Config.PodHomeDir = Prefix + "/var/pods"
		}
	}

	if Config.IamServiceUrlFrontend != "" && !strings.HasPrefix(Config.IamServiceUrlFrontend, "http") {
		return fmt.Errorf("Invalid iam_service_url_frontend")
	}

	if err := setupUser(); err != nil {
		return err
	}

	//
	if err := setupDataConnect(); err != nil {
		return err
	}

	return Config.Sync()
}

func setupHost() error {

	if len(Config.Host.Id) < 16 {
		Config.Host.Id = idhash.RandHexString(16)
		Config.Sync()
	}

	// Private IPv4
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
		Config.Host.SecretKey = idhash.RandBase64String(40)
		Config.Sync()
	}

	return nil
}

//

func setupDataConnect() error {

	conns := []types.NameIdentifier{
		"in_local_cache",
	}
	if IsZoneMaster() {
		conns = append(conns, []types.NameIdentifier{
			"in_zone_master",
			"in_global_master",
		}...)
	}

	for _, opName := range conns {
		opts := Config.IoConnectors.Options(opName)
		if opts == nil {
			opts = &connect.ConnOptions{
				Name:         opName,
				Connector:    "iomix/skv/connector",
				Driver:       types.NewNameIdentifier("lynkdb/kvgo"),
				DriverPlugin: types.NewNameIdentifier("lynkdb-kvgo.so"),
			}
		}
		if opts.Value("data_dir") == "" {
			opts.SetValue("data_dir", Prefix+"/var/"+string(opName))
		}
		Config.IoConnectors.SetOptions(*opts)
	}
	return nil
}

func setupUser() error {

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

func IsZoneMaster() bool {
	for _, v := range Config.Masters {
		if Config.Host.LanAddr == v {
			return true
		}
	}
	return false
}
