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

	"github.com/lynkdb/kvgo"
	kv2 "github.com/lynkdb/kvspec/go/kvspec/v2"

	"github.com/sysinner/incore/config"
)

var (
	DataLocal  kv2.Client
	DataZone   kv2.Client
	DataGlobal kv2.Client
	DataInpack kv2.Client
	err        error
)

func Setup() error {

	if config.Config.DataLocal != nil {
		if cn, err := kvgo.Open(config.Config.DataLocal); err != nil {
			return err
		} else {
			DataLocal, err = cn.NewClient()
			if err != nil {
				return err
			}
		}
	}

	if config.Config.DataZone != nil {
		if cn, err := kvgo.Open(config.Config.DataZone); err != nil {
			return err
		} else {
			DataZone, err = cn.NewClient()
			if err != nil {
				return err
			}
		}
	}

	if config.Config.DataGlobal != nil {
		if cn, err := kvgo.Open(config.Config.DataGlobal); err != nil {
			return err
		} else {
			DataGlobal, err = cn.NewClient()
			if err != nil {
				return err
			}
		}
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
