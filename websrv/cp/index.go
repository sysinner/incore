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
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/httpsrv"
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

	reqid := idhash.RandHexString(8)
	c.RenderString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
  <title>CP</title>
  <script src="/los/cp/~/lessui/js/sea.js?v=` + reqid + `"></script>
  <script src="/los/cp/~/cp/js/main.js?v=` + reqid + `"></script>
  <script type="text/javascript">
    window.onload = losCp.Boot(` + login + `);
  </script>
</head>

<body id="body-content">
<style>
._loscp_loading {
  margin: 0;
  padding: 30px 40px;
  font-size: 48px;
  color: #000;
}
</style>
<div class="_loscp_loading">loading</div>
</body>
</html>
`)
}
