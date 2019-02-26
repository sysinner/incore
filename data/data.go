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
	"github.com/lynkdb/iomix/skv"
	"github.com/lynkdb/kvgo"

	in_cfg "github.com/sysinner/incore/config"
)

var (
	LocalDB      skv.Connector
	ZoneMaster   skv.Connector
	GlobalMaster skv.Connector
	InpackData   skv.Connector
)

func Setup() error {

	for _, v := range in_cfg.Config.IoConnectors {

		switch v.Name {
		case "in_local_cache":
		case "in_zone_master":
		case "in_global_master":

		default:
			continue
		}

		var (
			db  skv.Connector
			err error
		)

		if v.Driver == "lynkdb/kvgo" {

			hlog.Printf("info", "DataConnector (%s) Open %s", v.Name, v.Driver)

			db, err = kvgo.Open(*v)

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

			db, err = fn(v)
		}

		if err != nil {
			return err
		}

		switch v.Name {
		case "in_local_cache":
			LocalDB = db

		case "in_zone_master":
			ZoneMaster = db

		case "in_global_master":
			GlobalMaster = db

		default:
			continue
		}

		hlog.Printf("info", "DataConnector (%s) OK", v.Name)
	}

	if LocalDB == nil {
		return fmt.Errorf("No DataConnector (%s) Setup", "in_local_cache")
	}

	if in_cfg.IsZoneMaster() {

		if ZoneMaster == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "in_zone_master")
		}
		if GlobalMaster == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "in_global_master")
		}
	}

	return nil
}
