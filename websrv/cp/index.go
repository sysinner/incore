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

package cp

import (
	"html"

	"github.com/hooto/httpsrv"
	"github.com/hooto/iam/iamclient"

	status "github.com/sysinner/incore/status"
	"github.com/sysinner/inpanel"
)

type Index struct {
	*httpsrv.Controller
}

func (c Index) IndexAction() {

	c.AutoRender = false
	c.Response.Out.Header().Set("Cache-Control", "no-cache")

	login := "false"
	if !iamclient.SessionIsLogin(c.Session) {
		login = "true"
	}

	cfgLogo, ok := status.ZoneSysConfigGroupList.Value("innerstack/sys/webui",
		"cp_navbar_logo")
	if !ok {
		cfgLogo = "/in/cp/~/cp/img/logo-g1s96.png"
	}

	cfgTitle, ok := status.ZoneSysConfigGroupList.Value("innerstack/sys/webui",
		"html_head_title")
	if !ok {
		cfgTitle = "InnerStack"
	} else {
		cfgTitle = html.EscapeString(cfgTitle)
	}

	c.RenderString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>` + cfgTitle + `</title>
  <script src="/in/cp/~/lessui/js/sea.js?v=` + inpanel.VersionHash + `"></script>
  <script src="/in/cp/~/cp/js/main.js?v=` + inpanel.VersionHash + `"></script>
  <link rel="stylesheet" href="/in/cp/~/cp/css/base.css?v=` + inpanel.VersionHash + `" type="text/css">
  <link rel="shortcut icon" type="image/x-icon" href="/in/cp/~/cp/img/favicon.png">
  <script type="text/javascript">
    inCp.version = "` + inpanel.VersionHash + `";
    inCp.zone_id = "` + inpanel.ZoneId + `";
    window.onload = inCp.Boot(` + login + `);
  </script>
</head>
<body id="body-content">
<div class="incp-well" id="incp-well">
<div class="incp-well-box">
  <div class="incp-well-panel">
    <div class="body2c">
      <div class="body2c1">
        <img src="` + cfgLogo + `">
      </div>
      <div class="body2c2">
        <div>InnerStack<br/>Open Enterprise PaaS Engine</div>
      </div>
    </div>
    <div class="status status_dark" id="incp-well-status">loading</div>
  </div>
  <div class="footer">
    <span class="copy">&copy;2019&nbsp;</span>
    <span class="url-info">Powered by <a href="https://www.sysinner.com" target="_blank">InnerStack</a></span>
  </div>
</div>
</div>
</body>
</html>
`)
}
