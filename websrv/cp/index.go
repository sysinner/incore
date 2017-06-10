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

package cp

import (
	"code.hooto.com/lessos/iam/iamclient"
	"github.com/lessos/lessgo/httpsrv"

	"code.hooto.com/lessos/los-webui"
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

	c.RenderString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
  <title>CP</title>
  <script src="/los/cp/~/lessui/js/sea.js?v=` + los_webui.Version + `"></script>
  <script src="/los/cp/~/cp/js/main.js?v=` + los_webui.Version + `"></script>
  <link rel="stylesheet" href="/los/cp/~/cp/css/main.css?v=` + los_webui.Version + `" type="text/css">
  <script type="text/javascript">
    losCp.version = "` + los_webui.Version + `";
    window.onload = losCp.Boot(` + login + `);
  </script>
</head>
<body id="body-content">
<div class="loscp-well" id="loscp-well">
<div class="loscp-well-box">
  <div class="loscp-well-panel">
    <div class="body2c">
      <div class="body2c1">
        <img src="/los/cp/~/cp/img/logo-g1s96.png">
      </div>
      <div class="body2c2">
        <div>Development Productivity Tools for DevOps</div>
      </div>
    </div>
    <div class="status status_dark" id="loscp-well-status">loading</div>
  </div>
  <div class="footer">
    <span class="copy">&copy;2017&nbsp;</span>
    <a href="http://www.lessos.com" target="_blank">lessOS.com</a>
  </div>
</div>
</div>
</body>
</html>
`)
}
