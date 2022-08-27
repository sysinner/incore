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

package inapi

import (
	"fmt"
	"regexp"

	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
)

type SysConfigurator struct {
	Name      string            `json:"name" toml:"name"`
	Title     string            `json:"title,omitempty" toml:"title,omitempty"`
	Fields    AppConfigFields   `json:"fields,omitempty" toml:"fields,omitempty"`
	ReadRoles types.ArrayUint32 `json:"read_roles,omitempty" toml:"read_roles,omitempty"`
}

type SysConfiguratorList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []*SysConfigurator `json:"items,omitempty" toml:"items,omitempty"`
}

type SysConfigGroup struct {
	Name    string       `json:"name" toml:"name"`
	Items   types.Labels `json:"items,omitempty" toml:"items,omitempty"`
	Updated uint32       `json:"updated,omitempty" toml:"updated,omitempty"`
}

type SysConfigGroupList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []*SysConfigGroup `json:"items,omitempty" toml:"items,omitempty"`
}

func (ls *SysConfigGroupList) Get(name string) *SysConfigGroup {
	for _, v := range ls.Items {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (ls *SysConfigGroupList) Value(groupName, itemName string) (string, bool) {
	if group := ls.Get(groupName); group != nil {
		for _, v := range group.Items {
			if v.Name == itemName {
				return v.Value, true
			}
		}
	}
	return "", false
}

func (ls *SysConfigGroupList) Sync(vn *SysConfigGroup) {

	for i, v := range ls.Items {
		if v.Name == vn.Name {
			if vn.Updated > v.Updated {
				ls.Items[i] = vn
			}
			return
		}
	}

	ls.Items = append(ls.Items, vn)
}

type SysConfigWizard struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Option         AppOption        `json:"option" toml:"option"`
	Configurator   *SysConfigurator `json:"configurator,omitempty" toml:"configurator,omitempty"`
}

type SysConfigWizardList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []*SysConfigWizard `json:"items,omitempty" toml:"items,omitempty"`
}

func (it *ConfigInstance) FieldValue(name string) string {
	for _, v := range it.Fields {
		if name == v.Name {
			return v.Value
		}
	}
	return ""
}

func ConfigInstanceApply(inst *ConfigInstance, spec *ConfigSpec) error {

	if inst == nil || inst.Name == "" {
		return fmt.Errorf("config instance not found")
	}

	if spec == nil {
		return fmt.Errorf("config spec name(%s) not found", inst.Name)
	}

	instSetup := ConfigInstance{}

	for _, field := range spec.Fields {

		var (
			value = inst.FieldValue(field.Name)
		)

		if field.AutoFill != "" {

			switch field.AutoFill {

			case AppConfigFieldAutoFillDefaultValue:
				if len(field.DefaultValue) < 1 {
					return fmt.Errorf("field(%s): DefaultValue empty", field.Name)
				}
				value = field.DefaultValue

			case AppConfigFieldAutoFillHexString_32:
				if len(value) < 32 {
					value = idhash.RandHexString(32)
				}

			case AppConfigFieldAutoFillBase64_48:
				if len(value) < 44 {
					value = idhash.RandBase64String(48)
				}

			default:
				return fmt.Errorf("field(%s): Not Dedault Value Type Found", field.Name)
			}
		}

		for _, validator := range field.Validates {
			if re, err := regexp.Compile(validator.Name); err == nil {
				if !re.MatchString(value) {
					return fmt.Errorf("field (%s): Invalid Value %s", field.Name, validator.Hint)
				}
			}
		}

		if len(value) > 0 {
			field := &ConfigFieldValue{
				Name:  field.Name,
				Value: value,
				Type:  field.Type,
			}
			if ls, _ := SliceMerge(instSetup.Fields, field, func(i int) bool {
				return instSetup.Fields[i].Name == field.Name
			}); ls != nil {
				instSetup.Fields = ls.([]*ConfigFieldValue)
			}
		}
	}

	inst.Fields = instSetup.Fields

	return nil
}
