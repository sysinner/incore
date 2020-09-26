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
	"errors"

	"github.com/lynkdb/kvgo"
	kv2 "github.com/lynkdb/kvspec/go/kvspec/v2"

	"github.com/sysinner/incore/config"
)

var (
	dbLocal    kv2.Client
	dbZone     kv2.Client
	DataLocal  kv2.ClientTable
	DataZone   kv2.ClientTable
	DataGlobal kv2.ClientTable
	DataInpack kv2.ClientTable
	err        error
)

func Setup() error {

	if err := setupLocal(); err != nil {
		return err
	}

	return nil
}

func setupLocal() error {

	if DataLocal == nil {

		cfgLocal := &kvgo.Config{
			Storage: kvgo.ConfigStorage{
				DataDirectory: config.Prefix + "/var/db_local",
			},
		}

		cn, err := kvgo.Open(cfgLocal)
		if err != nil {
			return err
		}
		dbLocal, err = cn.NewClient()
		if err != nil {
			return err
		}
		DataLocal = dbLocal.OpenTable("main")
	}

	return nil
}

func setupZone() error {

	if !config.IsZoneMaster() {
		return nil
	}

	if config.Config.ZoneMain == nil {
		return errors.New("no zone setup")
	}

	if config.Config.ZoneData == nil {

		config.Config.ZoneData = &kvgo.Config{
			Storage: kvgo.ConfigStorage{
				DataDirectory: config.Prefix + "/var/db_zone",
			},
		}

		if err = config.Config.Flush(); err != nil {
			return err
		}
	}

	cn, err := kvgo.Open(config.Config.ZoneData)
	if err != nil {
		return err
	}

	dbZone, err = cn.NewClient()
	if err != nil {
		return err
	}

	dbinit := func(name string) error {
		req := kv2.NewSysCmdRequest("TableSet", &kv2.TableSetRequest{
			Name: name,
			Desc: "innerstack " + name,
		})

		rs := dbZone.Connector().SysCmd(req)
		if !rs.OK() {
			return rs.Error()
		}
		return nil
	}

	flush := false

	//
	if DataZone == nil {
		if config.Config.ZoneMain.DataTableZone == "" {
			if err := dbinit("zone"); err != nil {
				return err
			}
			config.Config.ZoneMain.DataTableZone = "zone"
			flush = true
		}
		DataZone = dbZone.OpenTable(config.Config.ZoneMain.DataTableZone)
	}

	//
	if DataGlobal == nil {
		if config.Config.ZoneMain.DataTableGlobal == "" {
			if err := dbinit("global"); err != nil {
				return err
			}
			config.Config.ZoneMain.DataTableGlobal = "global"
			flush = true
		}
		DataGlobal = dbZone.OpenTable(config.Config.ZoneMain.DataTableGlobal)
	}

	//
	if DataInpack == nil {
		if config.Config.ZoneMain.DataTableInpack == "" {
			if err := dbinit("inpack"); err != nil {
				return err
			}
			config.Config.ZoneMain.DataTableInpack = "inpack"
			flush = true
		}
		DataInpack = dbZone.OpenTable(config.Config.ZoneMain.DataTableInpack)
	}

	if flush {
		if err = config.Config.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func Close() error {

	for _, db := range []kv2.Client{
		dbLocal,
		dbZone,
	} {
		if db != nil {
			db.Close()
		}
	}

	return nil
}
