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
	"fmt"

	"github.com/hooto/httpsrv"

	"github.com/sysinner/inpanel"
)

type Index struct {
	*httpsrv.Controller
}

func (c Index) IndexAction() {

	c.AutoRender = false
	c.Response.Out.Header().Set("Cache-Control", "no-cache")

	c.RenderString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
  <title>inPanel Ops</title>
  <script src="/in/ops/~/lessui/js/sea.js?v=` + inpanel.VersionHash + `"></script>
  <script src="/in/ops/~/ops/js/main.js?v=` + inpanel.VersionHash + `"></script>
  <link rel="shortcut icon" type="image/x-icon" href="/in/cp/~/cp/img/favicon.png">
  <script type="text/javascript">
    inOps.version = "` + inpanel.VersionHash + `";
    inOps.nav_cluster_zone = ` + fmt.Sprintf("%v", inpanel.OpsClusterZone) + `;
    inOps.nav_cluster_cell = ` + fmt.Sprintf("%v", inpanel.OpsClusterCell) + `;
    inOps.nav_cluster_host = ` + fmt.Sprintf("%v", inpanel.OpsClusterHost) + `;
    window.onload = inOps.Boot();
  </script>
</head>

<body id="body-content">
<style>
._inops_loading {
  margin: 0;
  padding: 30px 40px;
  font-size: 48px;
  color: #000;
}
</style>
<div class="_inops_loading">loading</div>
</body>
</html>
`)
}
