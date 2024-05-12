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
	"github.com/sysinner/incore/inapi"
)

func SysHostUpdate(zoneId string, host *inapi.ResHost) error {

	if zoneId == host.Operate.ZoneId {
		if rs := DataZone.NewWriter(
			inapi.NsZoneSysHost(zoneId, host.Meta.Id), host).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsGlobalSysHost(host.Operate.ZoneId, host.Meta.Id), host).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}

func SysHostDelete(zoneId string, host *inapi.ResHost) error {

	if zoneId == host.Operate.ZoneId {

		if rs := DataZone.NewWriter(
			inapi.NsKvZoneSysHostDestroyed(host.Operate.ZoneId, host.Meta.Id), host).Exec(); !rs.OK() {
			return rs.Error()
		}

		if rs := DataZone.NewDeleter(
			inapi.NsZoneSysHost(host.Operate.ZoneId, host.Meta.Id)).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsKvGlobalSysHostDestroyed(host.Operate.ZoneId, host.Meta.Id), host).Exec(); !rs.OK() {
		return rs.Error()
	}

	if rs := DataGlobal.NewDeleter(
		inapi.NsGlobalSysHost(host.Operate.ZoneId, host.Meta.Id)).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}

func SysCellUpdate(zoneId string, cell *inapi.ResCell) error {

	if zoneId == cell.ZoneId {
		if rs := DataZone.NewWriter(
			inapi.NsZoneSysCell(zoneId, cell.Meta.Id), cell).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id), cell).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}

func SysCellDelete(zoneId string, cell *inapi.ResCell) error {

	cell.Phase = inapi.OpActionDestroy | inapi.OpActionDestroyed

	if zoneId == cell.ZoneId {

		if rs := DataZone.NewWriter(
			inapi.NsKvZoneSysCellDestroyed(cell.ZoneId, cell.Meta.Id), cell).Exec(); !rs.OK() {
			return rs.Error()
		}

		if rs := DataZone.NewDeleter(
			inapi.NsZoneSysCell(cell.ZoneId, cell.Meta.Id)).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsKvGlobalSysCellDestroyed(cell.ZoneId, cell.Meta.Id), cell).Exec(); !rs.OK() {
		return rs.Error()
	}

	if rs := DataGlobal.NewDeleter(
		inapi.NsGlobalSysCell(cell.ZoneId, cell.Meta.Id)).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}

func SysZoneUpdate(zoneId string, zone *inapi.ResZone) error {

	if zoneId == zone.Meta.Id {
		if rs := DataZone.NewWriter(
			inapi.NsZoneSysZone(zone.Meta.Id), zone).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsGlobalSysZone(zone.Meta.Id), zone).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}

func SysZoneDelete(zoneId string, zone *inapi.ResZone) error {

	zone.Phase = inapi.OpActionDestroy | inapi.OpActionDestroyed

	if zoneId == zone.Meta.Id {
		if rs := DataZone.NewWriter(
			inapi.NsZoneSysZone(zone.Meta.Id), zone).Exec(); !rs.OK() {
			return rs.Error()
		}
	}

	if rs := DataGlobal.NewWriter(
		inapi.NsKvGlobalSysZoneDestroyed(zone.Meta.Id), zone).Exec(); !rs.OK() {
		return rs.Error()
	}

	if rs := DataGlobal.NewDeleter(
		inapi.NsGlobalSysZone(zone.Meta.Id)).Exec(); !rs.OK() {
		return rs.Error()
	}

	return nil
}
