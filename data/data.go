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

	"github.com/hooto/hlog4g/hlog"
	"github.com/lynkdb/iomix/sko"
	"github.com/lynkdb/kvgo"

	"github.com/sysinner/incore/config"
)

var (
	DataLocal  sko.ClientConnector
	DataZone   sko.ClientConnector
	DataGlobal sko.ClientConnector
	DataInpack sko.ClientConnector
)

func Setup() error {

	for _, v := range config.Config.IoConnectors {

		switch v.Name {
		case "db_local":
		case "db_zone":
		case "db_global":

		default:
			continue
		}

		var (
			db  interface{}
			err error
		)

		if v.Driver == "lynkdb/kvgo" {

			db, err = kvgo.Open(*v)

		} else {

			/**
			hlog.Printf("info", "DataConnector (%s) Plugin Open %s",
				v.Name, string(v.DriverPlugin))

			p, err := plugin.Open(config.Prefix + "/plugin/" + string(v.DriverPlugin))
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
			*/
		}

		if err != nil {
			return fmt.Errorf("setup %s err %s", v.Name, err.Error())
		}

		switch v.Name {
		case "db_local":
			DataLocal = db.(sko.ClientConnector)

		case "db_zone":
			DataZone = db.(sko.ClientConnector)

		case "db_global":
			DataGlobal = db.(sko.ClientConnector)

		default:
			continue
		}

		hlog.Printf("info", "DataConnector (%s) OK", v.Name)
	}

	if DataLocal == nil {
		return fmt.Errorf("No DataConnector (%s) Setup", "db_local")
	}

	if config.IsZoneMaster() {

		if DataZone == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "db_zone")
		}

		if DataGlobal == nil {
			return fmt.Errorf("No DataConnector (%s) Setup", "db_global")
		}
	}

	return nil
}
