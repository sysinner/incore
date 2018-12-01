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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/iomix/skv"
	"github.com/yhat/wsutil"

	"github.com/hooto/iam/iamapi"
	"github.com/hooto/iam/iamclient"
	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/data"
	"github.com/sysinner/incore/inapi"
	"github.com/sysinner/incore/inutils"
)

const (
	inagent_pod_json = "%s/%s.%s/home/action/.sysinner/pod_instance.json"
	inagent_sock     = "%s/%s.%s/home/action/.sysinner/inagent.sock"
)

var (
	inagent_dial_tto = 10 * time.Second
)

type Podbound struct {
	*httpsrv.Controller
	us iamapi.UserSession
}

func (c *Podbound) Init() int {

	//
	c.us, _ = iamclient.SessionInstance(c.Session)

	if !c.us.IsLogin() {
		c.Response.Out.WriteHeader(401)
		c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return 1
	}

	return 0
}

func (c *Podbound) owner_or_sysadmin_allow(user, privilege string) bool {
	if user == c.us.UserName ||
		iamclient.SessionAccessAllowed(c.Session, privilege, config.Config.InstanceId) {
		return true
	}
	return false
}

func (c Podbound) IndexAction() {

	c.AutoRender = false

	var pod_id = c.Params.Get("pod_id")
	if !inapi.PodIdReg.MatchString(pod_id) {
		c.Response.Out.WriteHeader(400)
		return
	}
	var rep_id = uint32(c.Params.Uint64("rep_id"))

	var pod inapi.Pod

	rs := data.LocalDB.PvGet(inapi.NsLocalCacheBoundPod(pod_id, rep_id))
	if rs.OK() {
		rs.Decode(&pod)
	} else if rs.NotFound() {

		json.DecodeFile(fmt.Sprintf(inagent_pod_json, config.Config.PodHomeDir, pod_id, inutils.Uint16ToHexString(uint16(rep_id))), &pod)

		if pod.Meta.ID == pod_id {
			data.LocalDB.PvPut(inapi.NsLocalCacheBoundPod(pod_id, rep_id), pod, &skv.KvProgWriteOptions{
				Expired: uint64(time.Now().Add(3600e9).UnixNano()),
			})
		}
	}

	if pod.Meta.ID != pod_id {
		c.Response.Out.WriteHeader(404)
		return
	}

	if !c.owner_or_sysadmin_allow(pod.Meta.User, "sysinner.admin") {
		c.Response.Out.WriteHeader(403)
		return
	}

	if c.Request.Method == "POST" || c.Request.Method == "PUT" {
		c.Request.Request.Body = ioutil.NopCloser(bytes.NewReader(c.Request.RawBody))
	}

	err := pclients.call(pod_id, rep_id, c.Request.Request, c.Response.Out)
	if err != nil {
		c.Response.Out.WriteHeader(500)
		hlog.Print("warn", err.Error())
	}
}

// proxy http/1.1 websocket/13
func PodBoundTerminalWsHandlerFunc(w http.ResponseWriter, r *http.Request) {

	pod_id := r.FormValue("pod_id")

	if !inapi.PodIdReg.MatchString(pod_id) {
		w.WriteHeader(400)
		return
	}
	rep_id, _ := strconv.Atoi(r.FormValue("rep_id"))
	if rep_id < 0 {
		rep_id = 0
	} else if rep_id >= 4096 {
		rep_id = 4095
	}

	tkv, err := r.Cookie(iamclient.AccessTokenKey)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	session, err := iamclient.Instance(tkv.Value)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	if !session.IsLogin() {
		w.WriteHeader(401)
		// c.RenderJson(types.NewTypeErrorMeta(iamapi.ErrCodeUnauthorized, "Unauthorized"))
		return
	}

	pod := pbPodInstanceSpec(pod_id, uint32(rep_id))
	if pod == nil {
		w.WriteHeader(400)
		return
	}

	if pod.Meta.User != session.UserName {
		w.WriteHeader(403)
		return
	}

	backendURL := &url.URL{Scheme: "ws://", Host: "127.0.0.1"}

	p := wsutil.NewSingleHostReverseProxy(backendURL)
	p.Dial = func(network, addr string) (net.Conn, error) {
		return net.Dial("unix", fmt.Sprintf(inagent_sock,
			config.Config.PodHomeDir, pod_id, inutils.Uint16ToHexString(uint16(rep_id))))
	}

	p.ServeHTTP(w, r)
}

func pbPodInstanceSpec(pod_id string, rep_id uint32) *inapi.Pod {

	var pod inapi.Pod

	rs := data.LocalDB.PvGet(inapi.NsLocalCacheBoundPod(pod_id, rep_id))
	if rs.OK() {
		rs.Decode(&pod)
	} else if rs.NotFound() {

		json.DecodeFile(fmt.Sprintf(inagent_pod_json, config.Config.PodHomeDir, pod_id, inutils.Uint16ToHexString(uint16(rep_id))), &pod)

		if pod.Meta.ID == pod_id {
			data.LocalDB.PvPut(inapi.NsLocalCacheBoundPod(pod_id, rep_id), pod, &skv.KvProgWriteOptions{
				Expired: uint64(time.Now().Add(3600e9).UnixNano()),
			})
		}
	}

	if pod.Meta.ID == pod_id {
		return &pod
	}

	return nil
}

// proxy http request/response
type podProxyUnixClients struct {
	clients map[string]*http.Client
	mu      sync.Mutex
}

func fakeDial(pod_id string, rep_id uint32) func(proto, addr string) (conn net.Conn, err error) {
	return func(proto, addr string) (conn net.Conn, err error) {
		return net.DialTimeout("unix", fmt.Sprintf(inagent_sock,
			config.Config.PodHomeDir, pod_id, inutils.Uint16ToHexString(uint16(rep_id))), inagent_dial_tto)
	}
}

var (
	pclients = podProxyUnixClients{
		clients: map[string]*http.Client{},
	}
)

func (fn *podProxyUnixClients) call(pod_id string, rep_id uint32, req *http.Request, rsp http.ResponseWriter) error {

	fn.mu.Lock()
	defer fn.mu.Unlock()

	req.URL.Scheme = "http"
	req.URL.Host = "127.0.0.1"
	req.RequestURI = ""

	prk := inapi.NsZonePodOpRepKey(pod_id, rep_id)

	client, ok := fn.clients[prk]
	if !ok {
		tr := &http.Transport{
			Dial: fakeDial(pod_id, rep_id),
		}
		client = &http.Client{Transport: tr}
		fn.clients[prk] = client
	}

	crsp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer crsp.Body.Close()

	for k, vs := range crsp.Header {
		for _, v := range vs {
			rsp.Header().Set(k, v)
		}
	}

	if crsp.ContentLength > 0 {
		var buf bytes.Buffer
		if _, err = buf.ReadFrom(crsp.Body); err != nil {
			return err
		}
		rsp.Write(buf.Bytes())
	}

	return nil
}
