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

package data

import (
	"fmt"
	"plugin"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lynkdb/iomix/connect"
	"github.com/lynkdb/iomix/sko"
	"github.com/lynkdb/iomix/skv"
	"github.com/lynkdb/kvgo"

	in_cfg "github.com/sysinner/incore/config"
	"github.com/sysinner/incore/version"
)

var (
	ZoneMaster   skv.Connector
	GlobalMaster skv.Connector
	LocalDB      sko.ClientConnector
	InpackData   sko.ClientConnector
	DataGlobal   sko.ClientConnector
	DataZone     sko.ClientConnector
)

func Setup() error {

	upgradeDriver := ""

	for _, v := range in_cfg.Config.IoConnectors {

		switch v.Name {
		case "in_zone_master":
		case "in_global_master":
		case "db_local":
		case "db_zone":
		case "db_global":

		default:
			continue
		}

		var (
			db  interface{} // skv.Connector
			err error
		)

		if v.Driver == "lynkdb/kvgo" {

			hlog.Printf("info", "DataConnector (%s) Open %s", v.Name, v.Driver)
			if v.Name[:3] == "db_" {
				db, err = kvgo.SkoOpen(*v)
			} else {
				db, err = kvgo.Open(*v)
			}

		} else {

			hlog.Printf("info", "DataConnector (%s) Plugin Open %s",
				v.Name, string(v.DriverPlugin))

			p, err := plugin.Open(in_cfg.Prefix + "/plugin/" + string(v.DriverPlugin))
			if err != nil {
				return err
			}

			nc, err := p.Lookup("NewConnector")
			if err != nil {
				return err
			}

			fn, ok := nc.(func(opts *connect.ConnOptions) (skv.Connector, error))
			if !ok {
				return fmt.Errorf("No Plugin/Method (%s) Found", "NewConnector")
			}

			upgradeDriver = "lynkstorgo"
			db, err = fn(v)
		}

		if err != nil {
			return fmt.Errorf("setup %s err %s", v.Name, err.Error())
		}

		switch v.Name {
		case "db_local":
			LocalDB = db.(sko.ClientConnector)

		case "db_zone":
			DataZone = db.(sko.ClientConnector)

		case "db_global":
			DataGlobal = db.(sko.ClientConnector)

		case "in_zone_master":
			ZoneMaster = db.(skv.Connector)

		case "in_global_master":
			GlobalMaster = db.(skv.Connector)

		default:
			continue
		}

		hlog.Printf("info", "DataConnector (%s) OK", v.Name)
	}

	if LocalDB == nil {
		return fmt.Errorf("No DataConnector (%s) Setup", "db_local")
	}

	if in_cfg.IsZoneMaster() {

		if GlobalMaster == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "global_master")
		}
		if ZoneMaster == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "zone_master")
		}

		if DataZone == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "db_zone")
		}
		if DataGlobal == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "db_global")
		}
	}

	if version.Version == "0.9.1" {

		if GlobalMaster != nil {
			if err := upgrade_v091(upgradeDriver, GlobalMaster, DataGlobal); err != nil {
				return err
			}
			hlog.Printf("info", "Upgrade GlobalMaster Done")
		}

		if ZoneMaster != nil {
			if err := upgrade_v091(upgradeDriver, ZoneMaster, DataZone); err != nil {
				return err
			}
			hlog.Printf("info", "Upgrade ZoneMaster Done")
		}
	}

	return nil
}
