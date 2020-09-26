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

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"github.com/sysinner/incore/inapi"
)

type configMergeCommand struct {
	cmd  *inapi.BaseCommand
	args struct {
		AppSpec         string
		WithConfigField string
		Config          string
	}
}

func NewConfigMergeCommand() *inapi.BaseCommand {

	c := &configMergeCommand{
		cmd: &inapi.BaseCommand{
			Use:   "config-merge",
			Short: "merge one of input text (json, yaml, toml, ini) to local config file",
			Long:  ``,
		},
	}

	c.cmd.Flags().StringVar(&c.args.AppSpec, "app-spec",
		"",
		`app-spec id`,
	)

	c.cmd.Flags().StringVar(&c.args.WithConfigField, "with-config-field",
		"",
		`path of config item
format:
  cfg/<app spec name>/<field name>
example:
  cfg/mysql-x1/server_ini
`)

	c.cmd.Flags().StringVar(&c.args.Config, "config",
		"",
		`the target config file path that merge to it`,
	)

	c.cmd.RunE = c.run

	return c.cmd
}

func (it *configMergeCommand) run(cmd *inapi.BaseCommand, args []string) error {

	if err := podSetup(); err != nil {
		return err
	}

	appCfr, err := appSetup(it.args.AppSpec)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(it.args.WithConfigField, "cfg/") {
		return errors.New("invalid --with-config-field value")
	}

	withConfigFields := strings.Split(it.args.WithConfigField, "/")
	if len(withConfigFields) < 3 {
		return errors.New("invalid --with-config-field value")
	}

	if it.args.Config == "" {
		return errors.New("--config file path not found")
	}

	field := appCfr.AppConfigField(strings.Join(withConfigFields[0:2], "/"), withConfigFields[2])
	if field == nil {
		return fmt.Errorf("config field (%s) not found", it.args.WithConfigField)
	}

	field.Value = strings.TrimSpace(field.Value)
	if field.Value == "" {
		return nil
	}

	cg := viper.New()
	cg.SetKeysCaseSensitive(true)

	switch field.Type {
	case inapi.AppConfigFieldTypeTextJSON:
		cg.SetConfigType("json")

	case inapi.AppConfigFieldTypeTextTOML:
		cg.SetConfigType("toml")

	case inapi.AppConfigFieldTypeTextYAML:
		cg.SetConfigType("yaml")

	case inapi.AppConfigFieldTypeTextINI:
		cg.SetConfigType("ini")

	case inapi.AppConfigFieldTypeTextJavaProperties:
		cg.SetConfigType("properties")

	default:
		return fmt.Errorf("field type(%d) not support", field.Type)
	}

	cg.SetConfigFile(it.args.Config)

	if err := cg.ReadInConfig(); err != nil {
		return err
	}

	if err := cg.MergeConfig(bytes.NewBuffer([]byte(field.Value))); err != nil {
		return err
	}

	if err := cg.WriteConfigAs(it.args.Config); err != nil {
		return err
	}

	return nil
}
