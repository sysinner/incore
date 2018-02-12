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
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"

	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/sysinner/incore/status"
)

type Zonebound struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Zonebound) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c Zonebound) IndexAction() {

	c.AutoRender = false

	var (
		zone_id  = c.Params.Get("zone_id")
		zone_api = ""
	)
	for _, v := range status.GlobalZones {
		if v.Meta.Id == zone_id && len(v.WanApi) > 0 {
			zone_api = v.WanApi
			break
		}
	}
	if zone_api == "" {
		c.Response.Out.WriteHeader(404)
		return
	}

	urls := strings.Replace(c.Request.URL.String(), "/in/v1/zonebound/"+zone_id+"/", "/in/v1/", -1)
	if strings.IndexByte(urls, '?') < 0 {
		urls += "?"
	} else {
		urls += "&"
	}
	urls += iamapi.AccessTokenKey + "=" + c.us.FullToken()

	urlr, err := url.Parse(zone_api + strings.Replace(c.Request.URL.String(), "/in/v1/zonebound/"+zone_id+"/", "/in/v1/", -1))
	if err != nil {
		c.Response.Out.WriteHeader(404)
		return
	}

	c.proxyHttpHandler(urlr)
}

func (c Zonebound) proxyHttpHandler(u *url.URL) {

	req, err := http.NewRequest(c.Request.Method, u.String(),
		ioutil.NopCloser(bytes.NewReader(c.Request.RawBody)))
	if err != nil {
		return
	}
	req.Header = c.Request.Header
	req.Host = u.Host

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = 200 * time.Millisecond

	proxy.ServeHTTP(c.Response.Out, req)
}
