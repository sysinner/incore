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

package v1

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/types"
	"golang.org/x/net/publicsuffix"

	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
)

var (
	resDomainRe1    = regexp.MustCompile("\\.+")
	resDomainRe2    = regexp.MustCompile("\\-+")
	resDomainPrefix = inapi.ResourceTypeDomain + "/"
	resDomainTypes  = types.ArrayString([]string{"pod", "upstream", "redirect"})
	resDomainPodRe2 = regexp.MustCompile("^[0-9a-f]{12,16}$")
)

func (c Resource) DomainListAction() {

	ls := inapi.ResourceList{}

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
		set inapi.Resource
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

	obj_name := fmt.Sprintf("%s/%s", inapi.ResourceTypeDomain, name)
	var prev inapi.Resource

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	set = prev

	set.Kind = "Resource"
}

func (c Resource) DomainNewAction() {

	var (
		set inapi.Resource
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

	if ar := strings.Split(set.Meta.Name, "."); len(ar) > 2 {

		obj_name_main := fmt.Sprintf("%s/%s", inapi.ResourceTypeDomain, strings.Join(ar[len(ar)-2:], "."))

		if rs := data.GlobalMaster.PvGet(inapi.NsGlobalResInstance(obj_name_main)); rs.OK() {
			var res inapi.Resource
			if err := rs.Decode(&res); err != nil {
				set.Error = types.NewErrorMeta(inapi.ErrCodeObjectExists, "Domain Exists")
				return
			}

			if res.Meta.User != c.us.UserName {
				set.Error = types.NewErrorMeta(inapi.ErrCodeObjectExists, "Domain signed ("+obj_name_main+") by another user")
				return
			}
		}
	}

	obj_name := fmt.Sprintf("%s/%s", inapi.ResourceTypeDomain, set.Meta.Name)
	inst := inapi.Resource{
		Meta: types.InnerObjectMeta{
			ID:      idhash.HashToHexString([]byte(obj_name), 16),
			Name:    obj_name,
			User:    c.us.UserName,
			Created: types.MetaTimeNow(),
			Updated: types.MetaTimeNow(),
		},
		Action: inapi.ResourceActionOK,
	}

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalResInstance(obj_name)); rs.OK() {
		set.Error = types.NewErrorMeta(inapi.ErrCodeObjectExists, "Domain Exists")
		return
	}

	//
	data.GlobalMaster.PvPut(inapi.NsGlobalResInstance(obj_name), inst, nil)

	set.Kind = "Resource"
}

func (c Resource) DomainSetAction() {

	var (
		set inapi.Resource
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

	obj_name := fmt.Sprintf("%s/%s", inapi.ResourceTypeDomain, set.Meta.Name)

	var (
		prev inapi.Resource
		sync = false
	)

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	if set.Meta.User != "" && set.Meta.User != prev.Meta.User {

		if err := iamapi.UserNameValid(set.Meta.User); err != nil {
			set.Error = types.NewErrorMeta("400", err.Error())
			return
		}

		ue := iamclient.PublicUserEntry(set.Meta.User)
		if ue.Error != nil {
			set.Error = types.NewErrorMeta("400", "User Not Found")
			return
		}

		prev.Meta.User, sync = set.Meta.User, true
	}

	if prev.Description != set.Description {
		prev.Description, sync = set.Description, true
	}

	if sync {
		prev.Meta.Updated = types.MetaTimeNow()
		data.GlobalMaster.PvPut(inapi.NsGlobalResInstance(obj_name), prev, nil)
	}

	set.Kind = "Resource"
}

func (c Resource) DomainBoundAction() {

	var set inapi.Resource

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

	obj_name := fmt.Sprintf("%s/%s", inapi.ResourceTypeDomain, set.Meta.Name)

	var prev inapi.Resource

	if rs := data.GlobalMaster.PvGet(inapi.NsGlobalResInstance(obj_name)); !rs.OK() {
		set.Error = types.NewErrorMeta("500", rs.Bytex().String())
		return
	} else if err := rs.Decode(&prev); err != nil {
		set.Error = types.NewErrorMeta("400", err.Error())
		return
	}

	if !c.owner_or_sysadmin_allow(prev.Meta.User, "sysinner.admin") {
		set.Error = types.NewErrorMeta(iamapi.ErrCodeAccessDenied, "AccessDenied")
		return
	}

	var sync bool

	for _, bd := range set.Bounds {

		bd.Value = strings.TrimSpace(strings.Replace(bd.Value, " ", "", -1))

		pi := strings.Index(bd.Value, ":")
		if pi < 1 {
			continue
		}

		var (
			bdtype  = bd.Value[:pi]
			bdvalue = bd.Value[pi+1:]
		)

		switch bdtype {
		case "pod":
			ups := strings.Split(bdvalue, ":")
			if len(ups) != 2 {
				set.Error = types.NewErrorMeta("400", "Invalid Pod ID:Port")
				return
			}
			if !resDomainPodRe2.MatchString(ups[0]) {
				set.Error = types.NewErrorMeta("400", "Invalid Pod ID:Port")
				return
			}

			/**
			bindPod := status.ZonePodList.Items.Get(ups[0])
			if bindPod == nil {
				set.Error = types.NewErrorMeta("400",
					fmt.Sprintf("Pod ID %s Not Found"), ups[0])
				return
			}
			*/

			if port, err := strconv.Atoi(ups[1]); err != nil || port < 80 || port > 65505 {
				set.Error = types.NewErrorMeta("400", "Invalid Pod ID:Port")
				return
			}

		case "upstream":
			ups := strings.Split(bdvalue, ";")
			for _, upv := range ups {

				vs := strings.Split(upv, ":")
				if len(vs) != 2 {
					set.Error = types.NewErrorMeta("400", "Invalid IP:Port")
					return
				}

				if ip := net.ParseIP(vs[0]); ip == nil || ip.To4() == nil {
					set.Error = types.NewErrorMeta("400", "Invalid IP:Port")
					return
				}
				if port, err := strconv.Atoi(vs[1]); err != nil || port < 80 || port > 65505 {
					set.Error = types.NewErrorMeta("400", "Invalid IP:Port")
					return
				}
			}

		case "redirect":
			uri, err := url.ParseRequestURI(bdvalue)
			if err != nil {
				set.Error = types.NewErrorMeta("400", "Invalid Redirect URL or Path: "+err.Error())
				return
			}
			uri.Path = filepath.Clean(uri.Path)
			if uri.Path == "." {
				uri.Path = "/"
			}
			bd.Value = "redirect:" + uri.String()

		default:
			set.Error = types.NewErrorMeta("400", "Invalid Bound Type")
			return
		}

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
		data.GlobalMaster.PvPut(inapi.NsGlobalResInstance(obj_name), prev, nil)
	}

	set.Kind = "Resource"
}
