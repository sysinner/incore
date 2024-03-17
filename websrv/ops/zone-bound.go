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

package ops

import (
	"bytes"
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
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized #02"))
		return 1
	}

	return 0
}

func (c Zonebound) IndexAction() {

	c.AutoRender = false

	var (
		zone_id  = c.Params.Value("zone_id")
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
	zone_url, err := url.Parse(zone_api)
	if err != nil {
		c.Response.Out.WriteHeader(404)
		return
	}

	url_path := strings.Replace(c.Request.URL.String(),
		"/in/ops/zonebound/"+zone_id+"/", "/in/ops/", -1)
	if strings.IndexByte(url_path, '?') < 0 {
		url_path += "?"
	} else {
		url_path += "&"
	}
	url_path += iamapi.AccessTokenKey + "=" + c.us.AccessToken

	proxy_url, err := url.Parse(url_path)
	if err != nil {
		c.Response.Out.WriteHeader(404)
		return
	}

	c.proxyHttpHandler(zone_url, proxy_url)
}

func (c Zonebound) proxyHttpHandler(proxy_endpoint *url.URL, proxy_url *url.URL) {

	req, err := http.NewRequest(c.Request.Method, proxy_url.String(),
		bytes.NewReader(c.Request.RawBody()))
	if err != nil {
		return
	}
	// req.Header = c.Request.Header
	// req.Host = proxy_url.Host

	proxy := httputil.NewSingleHostReverseProxy(proxy_endpoint)
	proxy.FlushInterval = 200 * time.Millisecond

	proxy.ServeHTTP(c.Response.Out, req)
}
