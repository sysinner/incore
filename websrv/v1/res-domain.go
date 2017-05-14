// Copyright 2015 Authors, All rights reserved.
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

package v1

import (
	"fmt"
	"regexp"
	"strings"

	"code.hooto.com/lessos/iam/iamapi"
	"code.hooto.com/lynkdb/iomix/skv"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	"golang.org/x/net/publicsuffix"

	"code.hooto.com/lessos/loscore/data"
	"code.hooto.com/lessos/loscore/losapi"
)

var (
	resDomainRe1    = regexp.MustCompile("\\.+")
	resDomainRe2    = regexp.MustCompile("\\-+")
	resDomainPrefix = losapi.ResourceTypeDomain + "/"
)

func (c Resource) DomainListAction() {

	ls := losapi.ResourceList{}

	defer c.RenderJson(&ls)

	ls.Kind = "ResourceList"
}

func domain_name_filter(domain string) string {

	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))

	domain = resDomainRe1.ReplaceAllString(resDomainRe2.ReplaceAllString(domain, "-"), ".")

	if strings.HasPrefix(domain, resDomainPrefix) {
		domain = domain[len(resDomainPrefix):]
	}

	return domain
}

func (c Resource) DomainAction() {

	var (
		set losapi.Resource
	)

	defer c.RenderJson(&set)

	name := domain_name_filter(c.Params.Get("name"))

	if name == "" || len(name) > 50 {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name")
		return
	}

	if _, ok := publicsuffix.PublicSuffix(name); !ok {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name (TLD)")
		return
	}

	obj_name := fmt.Sprintf("%s/%s", losapi.ResourceTypeDomain, name)
	var prev losapi.Resource

	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	set = prev

	set.Kind = "Resource"
}

func (c Resource) DomainNewAction() {

	var (
		set losapi.Resource
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	set.Meta.Name = domain_name_filter(set.Meta.Name)

	if set.Meta.Name == "" || len(set.Meta.Name) > 50 {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name")
		return
	}

	if _, ok := publicsuffix.PublicSuffix(set.Meta.Name); !ok {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name (TLD)")
		return
	}

	obj_name := fmt.Sprintf("%s/%s", losapi.ResourceTypeDomain, set.Meta.Name)

	inst := losapi.Resource{
		Meta: types.InnerObjectMeta{
			ID:      idhash.HashToHexString([]byte(obj_name), 16),
			Name:    obj_name,
			User:    c.us.UserName,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Action: losapi.ResourceActionOK,
	}

	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalResInstance(obj_name)); rs.OK() {
		set.Error = types.NewErrorMeta(losapi.ErrCodeObjectExists, "Domain Exists")
		return
	}

	//
	data.ZoneMaster.PvPut(losapi.NsGlobalResInstance(obj_name), inst, &skv.PvWriteOptions{
		Force: true,
	})

	set.Kind = "Resource"
}

func (c Resource) DomainSetAction() {

	var (
		set losapi.Resource
	)

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	set.Meta.Name = domain_name_filter(set.Meta.Name)

	if set.Meta.Name == "" || len(set.Meta.Name) > 50 {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name")
		return
	}

	if _, ok := publicsuffix.PublicSuffix(set.Meta.Name); !ok {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name (TLD)")
		return
	}

	obj_name := fmt.Sprintf("%s/%s", losapi.ResourceTypeDomain, set.Meta.Name)

	var prev losapi.Resource

	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if prev.Description != set.Description {

		prev.Description = set.Description
		prev.Meta.Updated = types.MetaTimeNow()

		//
		data.ZoneMaster.PvPut(losapi.NsGlobalResInstance(obj_name), prev, &skv.PvWriteOptions{
			Force: true,
		})
	}

	set.Kind = "Resource"
}

func (c Resource) DomainBoundAction() {

	var set losapi.Resource

	defer c.RenderJson(&set)

	if err := c.Request.JsonDecode(&set); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	set.Meta.Name = domain_name_filter(set.Meta.Name)

	if set.Meta.Name == "" || len(set.Meta.Name) > 50 {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name")
		return
	}

	if _, ok := publicsuffix.PublicSuffix(set.Meta.Name); !ok {
		set.Error = types.NewErrorMeta("400", "Invalid Domain Name (TLD)")
		return
	}

	obj_name := fmt.Sprintf("%s/%s", losapi.ResourceTypeDomain, set.Meta.Name)

	var prev losapi.Resource

	if rs := data.ZoneMaster.PvGet(losapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if prev.Meta.User != c.us.UserName {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	var sync bool

	for _, bd := range set.Bounds {

		if chg, err := prev.Bounds.Sync(*bd); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		} else if chg {
			sync = true
		}
	}

	if sync {

		prev.Meta.Updated = types.MetaTimeNow()
		//
		data.ZoneMaster.PvPut(losapi.NsGlobalResInstance(obj_name), prev, &skv.PvWriteOptions{
			Force: true,
		})
	}

	set.Kind = "Resource"
}
