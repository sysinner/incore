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

package zonemaster

import (
	"fmt"
	"time"

	"github.com/hooto/hlang4g/hlang"
	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/crypto/idhash"

	iam_cfg "github.com/hooto/iam/config"
	iam_db "github.com/hooto/iam/data"
	iam_cli "github.com/hooto/iam/iamclient"
	iam_web "github.com/hooto/iam/websrv/ctrl"
	iam_v1 "github.com/hooto/iam/websrv/v1"
	iamWorker "github.com/hooto/iam/worker"

	ip_cfg "github.com/sysinner/inpack/server/config"
	ip_db "github.com/sysinner/inpack/server/data"
	ip_p1 "github.com/sysinner/inpack/websrv/p1"
	ip_v1 "github.com/sysinner/inpack/websrv/v1"

	ic_ws_cp "github.com/sysinner/incore/websrv/cp"
	ic_ws_op "github.com/sysinner/incore/websrv/ops"
	ic_ws_p1 "github.com/sysinner/incore/websrv/p1"
	ic_ws_v1 "github.com/sysinner/incore/websrv/v1"
	ic_ws_ui "github.com/sysinner/inpanel"

	incfg "github.com/sysinner/incore/config"
	ic_db "github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/injob"
	instatus "github.com/sysinner/incore/status"

	is_cfg "github.com/sysinner/innerstack/config"
)

type ZoneMainJob struct {
	spec   *injob.JobSpec
	inited bool
	hs     *httpsrv.Service
}

var (
	err error
)

func NewZoneMainJob() *injob.JobEntry {
	return injob.NewJobEntry(&ZoneMainJob{},
		injob.NewSchedule().EveryTimeCycle(injob.Second, 3))
}

func (it *ZoneMainJob) Spec() *injob.JobSpec {
	if it.spec == nil {
		it.spec = injob.NewJobSpec("zone/main").
			ConditionSet("zone/main-node", -1)
	}
	return it.spec
}

func (it *ZoneMainJob) Status() *injob.Status {
	return nil
}

func (it *ZoneMainJob) Run(ctx *injob.Context) error {

	if !incfg.IsZoneMaster() {
		return nil
	}

	if !it.inited {
		if err := it.init(); err != nil {
			return err
		}
		it.inited = true
	}

	zoneTracker()

	zmWorkerMasterLeaderRefresh()

	if instatus.IsZoneMasterLeader() {

		if err := scheduleAction(); err != nil {
			hlog.Printf("warn", "zm/scheduler err:%s", err.Error())
		}

		if err := podChargeRefresh(); err != nil {
			hlog.Printf("warn", "zm/pod/charge err:%s", err.Error())
		}

		instatus.ZoneScheduled = time.Now().Unix()

		go iamWorker.AccountChargeCloseRefresh()
		go iamWorker.MsgQueueRefresh()
	}

	return nil
}

func (it *ZoneMainJob) init() error {

	if it.hs == nil {

		it.hs = httpsrv.NewService()
		it.hs.Config.TemplateFuncRegister("T", hlang.StdLangFeed.Translate)

		hlog.Printf("info", "inPack %s", ip_cfg.Version)
		hlog.Printf("info", "inPanel %s", ic_ws_ui.Version)

		ic_ws_ui.VersionHash = idhash.HashToHexString([]byte(
			(is_cfg.Version + is_cfg.Release)), 16)
		ic_ws_ui.ZoneId = incfg.Config.Host.ZoneId

		if incfg.Config.ZoneMain != nil &&
			incfg.Config.ZoneMain.MultiHostEnable {
			ic_ws_ui.OpsClusterHost = true
			if incfg.Config.ZoneMain.MultiCellEnable {
				ic_ws_ui.OpsClusterCell = true
				if incfg.Config.ZoneMain.MultiZoneEnable {
					ic_ws_ui.OpsClusterZone = true
				}
			}
		}

	}

	// module/IAM
	{

		if incfg.Config.IamService == nil {
			incfg.Config.IamService = &iam_cfg.ConfigCommon{}
		}

		//
		if err := iam_cfg.SetupConfig(
			incfg.Prefix+"/vendor/github.com/hooto/iam",
			incfg.Config.IamService,
		); err != nil {
			return fmt.Errorf("iam_cfg.InitConfig error: %s", err.Error())
		}

		iam_cfg.Config.InstanceID = "00" + idhash.HashToHexString([]byte("innerstack/iam"), 14)
		iam_cfg.VersionHash = idhash.HashToHexString([]byte(
			(iam_cfg.Config.InstanceID + iam_cfg.Version)), 16)

		// init database
		iam_db.Data = ic_db.DataGlobal
		if err := iam_db.Setup(); err != nil {
			return fmt.Errorf("iam.Store.Init error: %s", err.Error())
		}
		if err := iam_db.InitData(); err != nil {
			return fmt.Errorf("iam.Store.InitData error: %s", err.Error())
		}
		iam_db.SysConfigRefresh()

		//
		it.hs.ModuleRegister("/iam/v1", iam_v1.NewModule())
		it.hs.ModuleRegister("/iam", iam_web.NewModule())

		//
		if aks := is_cfg.InitIamAccessKeyData(); len(aks) > 0 {
			for _, v := range aks {
				iam_db.AccessKeyInitData(&v)
			}
		}

		if incfg.Config.ZoneMain.IamAccessKey != nil {
			iam_db.AccessKeyInitData(incfg.Config.ZoneMain.IamAccessKey)
		}
	}

	{
		//
		iam_cli.ServiceUrl = fmt.Sprintf(
			"http://%s:%d/iam",
			inapi.HostNodeAddress(incfg.Config.Host.LanAddr).IP(),
			incfg.Config.Zone.HttpPort,
		)
		if incfg.Config.Zone.IamServiceUrlFrontend == "" {
			if inapi.HostNodeAddress(incfg.Config.Host.WanAddr).IP() != "" {
				iam_cli.ServiceUrlFrontend = fmt.Sprintf(
					"http://%s:%d/iam",
					inapi.HostNodeAddress(incfg.Config.Host.WanAddr).IP(),
					incfg.Config.Zone.HttpPort,
				)
			} else {
				iam_cli.ServiceUrlFrontend = iam_cli.ServiceUrl
			}
		} else {
			iam_cli.ServiceUrlFrontend = incfg.Config.Zone.IamServiceUrlFrontend
		}

		if incfg.Config.Zone.IamServiceUrlGlobal != "" {
			iam_cli.ServiceUrlGlobal = incfg.Config.Zone.IamServiceUrlGlobal
		}

		hlog.Printf("info", "IAM ServiceUrl %s", iam_cli.ServiceUrl)
		hlog.Printf("info", "IAM ServiceUrlFrontend %s", iam_cli.ServiceUrlFrontend)

		if incfg.Config.Zone.IamServiceUrlGlobal != "" {
			iam_cli.ServiceUrlGlobal = incfg.Config.Zone.IamServiceUrlGlobal
			hlog.Printf("info", "IAM ServiceUrlGlobal %s", iam_cli.ServiceUrlGlobal)
		}
	}

	// module/IPS: init ips database and webserver
	{

		if err = ip_cfg.Setup(incfg.Prefix); err != nil {
			return fmt.Errorf("ips.Config.Init error: %s", err.Error())
		}

		// init inpack database
		if err = ip_db.Setup(); err != nil {
			return fmt.Errorf("ip_db setup failed:%s", err.Error())
		}
		ip_db.Data = ic_db.DataInpack
		// ic_db.DataInpack = ip_db.Data

		// TODEL
		ip_cfg.Config.Sync()

		if err := iam_db.AppInstanceRegister(ip_cfg.IamAppInstance()); err != nil {
			return fmt.Errorf("ips.Data.Init error: %s", err.Error())
		}

		it.hs.ModuleRegister("/ips/v1", ip_v1.NewModule())
		it.hs.ModuleRegister("/ips/p1", ip_p1.NewModule())
		it.hs.ModuleRegister("/in/cp/ips/~", httpsrv.NewStaticModule("ip_ui", incfg.Prefix+"/webui/ips"))

		// TODO
		incfg.Config.Zone.InpackServiceUrl = fmt.Sprintf(
			"http://%s:%d/",
			inapi.HostNodeAddress(incfg.Config.Host.LanAddr).IP(),
			incfg.Config.Zone.HttpPort,
		)

		//
		if aks := ip_cfg.InitIamAccessKeyData(); len(aks) > 0 {
			for _, v := range aks {
				iam_db.AccessKeyInitData(&v)
			}
		}
	}

	// module/hchart
	{
		it.hs.ModuleRegister("/in/cp/hchart/~", httpsrv.NewStaticModule("hchart_ui", incfg.Prefix+"/webui/hchart/webui"))
		it.hs.ModuleRegister("/in/ops/hchart/~", httpsrv.NewStaticModule("hchart_ui_ops", incfg.Prefix+"/webui/hchart/webui"))
	}

	// incore
	{

		ic_inst := is_cfg.IamAppInstance()
		if err := iam_db.AppInstanceRegister(ic_inst); err != nil {
			return fmt.Errorf("in.Data.Init error: %s", err.Error())
		}
		incfg.Config.Zone.InstanceId = ic_inst.Meta.ID
		incfg.Config.Flush()

		it.hs.HandlerFuncRegister("/in/v1/pb/termws", ic_ws_v1.PodBoundTerminalWsHandlerFunc)

		// Frontend APIs for Users
		it.hs.ModuleRegister("/in/v1", ic_ws_v1.NewModule())

		// Frontend UI for Users
		hlang.StdLangFeed.LoadMessages(incfg.Prefix+"/i18n/en.json", true)
		hlang.StdLangFeed.LoadMessages(incfg.Prefix+"/i18n/zh-CN.json", true)

		it.hs.Config.TemplateFuncRegister("T", hlang.StdLangFeed.Translate)

		ic_ws_m := ic_ws_cp.NewModule()
		ic_ws_m.ControllerRegister(new(hlang.Langsrv))

		it.hs.ModuleRegister("/in/cp", ic_ws_m)

		// Backend Operating APIs/UI for System Operators
		it.hs.ModuleRegister("/in/ops", ic_ws_op.NewModule())

		// Frontend UI Index
		it.hs.ModuleRegister("/in/p1", ic_ws_p1.NewModule())
		it.hs.ModuleRegister("/in", ic_ws_cp.NewIndexModule())
	}

	// init zonemaster
	{
		if err := InitData(is_cfg.InitZoneMasterData()); err != nil {
			return fmt.Errorf("ic_zm.InitData err %s", err.Error())
		}

		if err := SetupScheduler(); err != nil {
			return fmt.Errorf("ic_zm.SetupScheduler err %s", err.Error())
		}

		if err := instatus.ZoneMailManager.TemplateLoad(incfg.Prefix + "/etc"); err != nil {
			hlog.Printf("warn", "zm/mail-manager template load err %e", err.Error())
		}
	}

	it.hs.Config.HttpPort = incfg.Config.Zone.HttpPort
	go it.hs.Start()

	return nil
}
