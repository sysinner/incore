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

package inservice

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	_ "embed"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/hooto/hmetrics"
	"github.com/hooto/htoml4g/htoml"
	"github.com/lessos/lessgo/types"
	"github.com/lynkdb/lynkapi/go/lynkapi"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sysinner/incore/inutils/tplrender"
	inapi2 "github.com/sysinner/incore/v2/inapi"
	"github.com/sysinner/incore/v2/pkg/signals"
)

//go:embed builtin/404.html
var builtin_404_HTML []byte

//go:embed module/domain-sale.html
var module_DomainSale_HTML string

func Run() {

	mrand.Seed(time.Now().UnixNano())

	mux := http.NewServeMux()
	// mux.HandleFunc("/", cmpHandler(httpHandler))
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/+/metrics", hmetrics.HttpHandler)

	os.MkdirAll(tlsCacheDir, 0750)

	certManager = autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(tlsCacheDir),
		HostPolicy: autocert.HostWhitelist(tlsDomainSet...),
	}

	{
		for {

			if err := initSetup(); err != nil {
				hlog.Printf("error", "init config fail : %s", err.Error())
				time.Sleep(1e9)
			} else {
				break
			}
		}

		if err := configRefresh(cfg.Domains); err != nil {
			hlog.Printf("error", "domains init fail : %s", err.Error())
		} else {
			hlog.Printf("info", "domains (%d) init ok", len(cfg.Domains))
		}
	}

	{
		httpServer = &http.Server{
			Addr: ":80",
			// Handler: certManager.HTTPHandler(nil),
			Handler: httpRootHandler{},
		}
		signals.AddGo(func() {
			defer signals.DeferDone()
			if err := httpServer.ListenAndServe(); err != nil {
				hlog.Printf("error", "http server start failed : %s", err.Error())
			}
			hlog.Printf("info", "http server quit")
		}, func() {
			httpServer.Shutdown(context.Background())
		})
	}

	{
		httpsServer = &http.Server{
			Addr:    ":443",
			Handler: mux,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		signals.AddGo(func() {
			defer signals.DeferDone()
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
				hlog.Printf("error", "https server start failed : %s", err.Error())
			}
			tlsDomainCache = nil
			hlog.Printf("info", "https server quit")
		}, func() {
			httpsServer.Shutdown(context.Background())
		})
	}

	if cfg.Zone != nil {
		signals.AddGo(func() {

			ticker := time.NewTicker(time.Second * 10)
			defer ticker.Stop()

			for {
				select {
				case <-signals.Done():
					return

				case <-ticker.C:
					if err := configRefresh(nil); err != nil {
						hlog.Printf("error", "domains refresh fail : %s", err.Error())
					}
				}
			}
		}, nil)
	}

	signals.Wait()
}

type Config struct {
	mu sync.RWMutex

	Zone *ConfigZone `toml:"zone,omitempty"`

	Modules      []*ConfigModule          `toml:"modules"`
	indexModules map[string]*ConfigModule `toml:"-"`

	Domains      []*inapi2.GatewayService_DomainDeploy `toml:"domains"`
	indexDomains map[string]*DomainEntry               `toml:"-"`

	lastVersion     uint64
	lastFullUpdated int64
}

type ConfigZone struct {
	Id     string               `toml:"id"`
	Client lynkapi.ClientConfig `toml:"client"`
}

type ConfigModule struct {
	Module  string            `toml:"module"`
	Domains []string          `toml:"domains"`
	Options map[string]string `toml:"options,omitempty"`

	handler ModuleHandler
}

func (it *Config) Domain(name string) *DomainEntry {
	it.mu.RLock()
	defer it.mu.RUnlock()
	domain, ok := it.indexDomains[name]
	if ok {
		return domain
	}
	return nil
}

func (it *Config) Module(domain string) *ConfigModule {
	it.mu.RLock()
	defer it.mu.RUnlock()
	m, ok := it.indexModules[domain]
	if ok {
		return m
	}
	return nil
}

type DomainEntry struct {
	Domain *inapi2.GatewayService_DomainDeploy `json:"domain"`
	Routes []*DomainEntryRoute                 `json:"routes"`

	setupVersion uint64
}

type DomainEntryRoute struct {
	Type string     `json:"type"`
	Path string     `json:"path"`
	Urls []*url.URL `json:"urls"`
}

var (
	prefix = "/opt/sysinner/inservice"

	tlsCacheDir = prefix + "/var/tls_cache"

	tlsDomainSet   = []string{}
	tlsDomainCache = []string{}

	httpServer  *http.Server
	httpsServer *http.Server

	certManager autocert.Manager

	version = "0.11"
	release = "0"

	cfg Config

	lynkClient lynkapi.Client

	mainQuit = false
)

var (
	metricCounter = hmetrics.RegisterCounterMap(
		"counter",
		"The General Counter Metric",
	)

	metricGauge = hmetrics.RegisterGaugeMap(
		"gauge",
		"The General Gauge Metric",
	)

	metricLatency = hmetrics.RegisterHistogramMap(
		"latency",
		"The General Latency Metric",
		hmetrics.NewBuckets(0.0001, 1.5, 36),
	)

	metricHistogram = hmetrics.RegisterHistogramMap(
		"histogram",
		"The General Histogram Metric",
		hmetrics.NewBuckets(0.0001, 1.5, 36),
	)

	metricComplex = hmetrics.RegisterComplexMap(
		"complex",
		"The General Complex Metric",
		hmetrics.NewBuckets(0.0001, 1.5, 36),
	)
)

func initSetup() error {

	if err := htoml.DecodeFromFile(prefix+"/etc/config.toml", &cfg); err != nil {
		return err
	}

	cfg.indexDomains = map[string]*DomainEntry{}

	cfg.indexModules = map[string]*ConfigModule{}
	for _, module := range cfg.Modules {
		switch module.Module {
		case "DomainSale":
			if len(module.Options) > 0 && module.Options["contact_email"] != "" {
				module.handler = module_DomainSale_Handler
				for _, d := range module.Domains {
					cfg.indexModules[strings.ToLower(d)] = module
					hlog.Printf("info", "module %s domain %s", module.Module, d)
				}
			}
		}
	}

	if lynkClient == nil && cfg.Zone != nil {
		if c, err := cfg.Zone.Client.NewClient(); err != nil {
			return err
		} else {
			lynkClient = c
		}
	}

	return nil
}

func configRefresh(domains []*inapi2.GatewayService_DomainDeploy) error {

	tn := time.Now().Unix()
	req := &inapi2.GatewayService_DomainDeployListRequest{}

	if len(domains) == 0 && cfg.Zone != nil {

		req.ZoneId = cfg.Zone.Id

		if cfg.lastFullUpdated+600 < tn {
			req.Version = 0
			cfg.lastFullUpdated = tn
		} else {
			req.Version = cfg.lastVersion
		}

		rsp := lynkClient.Exec(lynkapi.NewRequest("Zonelet", "GatewayDomainDeployList", req))
		if !rsp.OK() {
			return rsp.Err()
		}

		var rspList inapi2.GatewayService_DomainDeployListResponse
		if err := rsp.Decode(&rspList); err != nil {
			return err
		}

		if len(rspList.Domains) == 0 {
			return nil
		}

		if req.Version == 0 && len(cfg.Domains) > 0 {
			r := float64(len(rspList.Domains)) / float64(len(cfg.Domains))
			if r < 0.5 {
				hlog.Printf("info", "fetch domains %d/%d, skip", len(rspList.Domains), len(cfg.Domains))
				return nil
			}
		}

		domains = rspList.Domains

		hlog.Printf("info", "req version %d, fetch domains %d", req.Version, len(rspList.Domains))
	}

	var (
		newDomains   = []*inapi2.GatewayService_DomainDeploy{}
		tlsDomainSet = []string{}
		flush        = false
	)

	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	// hlog.Printf("info", "App Options %d", len(appCfr.App.Operate.Options))
	for _, domain := range domains {
		//
		domainEntry, added := cfg.indexDomains[domain.Name]
		if !added {
			domainEntry = &DomainEntry{
				Domain: domain,
			}
			hlog.Printf("info", "add domain %s, routes %d", domain.Name, len(domain.Locations))
		}

		cfg.lastVersion = max(cfg.lastVersion, domain.Version)

		if !added || domain.Version > domainEntry.setupVersion {

			flush = true
			domainEntry.Routes = nil
			domainEntry.setupVersion = domain.Version

			for _, location := range domain.Locations {

				switch location.Type {
				case "pod", "upstream":
					var urls []*url.URL
					for _, addr := range location.Targets {
						urls = append(urls, &url.URL{
							Scheme: "http",
							Host:   addr,
						})
					}
					if len(urls) > 0 {
						domainEntry.Routes = append(domainEntry.Routes, &DomainEntryRoute{
							Path: location.Path,
							Type: location.Type,
							Urls: urls,
						})
					}

				case "redirect":

					if u, err := url.Parse(location.TargetUrl); err == nil {

						domainEntry.Routes = append(domainEntry.Routes, &DomainEntryRoute{
							Path: location.Path,
							Type: location.Type,
							Urls: []*url.URL{u},
						})
					}
				}
			}

			hlog.Printf("info", "updated domain %s, routes %d", domain.Name, len(domain.Locations))
		}

		//
		if len(domainEntry.Routes) == 0 {
			continue
		}

		// locations
		sort.Slice(domainEntry.Routes, func(i, j int) bool {
			return strings.Compare(domainEntry.Routes[i].Path, domainEntry.Routes[j].Path) > 0
		})

		if domain.LetsencryptEnable {
			tlsDomainSet, _ = types.ArrayStringSet(tlsDomainSet, domain.Name)
		}

		if !added {
			cfg.indexDomains[domain.Name] = domainEntry
		}

		newDomains = append(newDomains, domain)
	}

	if req.Version == 0 &&
		(len(newDomains) != len(cfg.indexDomains) ||
			len(newDomains) != len(cfg.Domains)) {

		hlog.Printf("info", "cfg domains %d, new domains %d, setup %d",
			len(cfg.Domains), len(newDomains), len(cfg.indexDomains))

		for _, domain := range cfg.Domains {
			if p := lynkapi.SlicesSearchFunc(newDomains, func(a *inapi2.GatewayService_DomainDeploy) bool {
				return a.Name == domain.Name
			}); p == nil {
				delete(cfg.indexDomains, domain.Name)
				hlog.Printf("info", "delete domain %s", domain.Name)
			}
		}
		flush = true
		hlog.Printf("info", "setup domains %d to %d", len(cfg.Domains), len(newDomains))
		cfg.Domains = newDomains
	}

	if len(tlsDomainSet) > 0 &&
		types.ArrayStringHit(tlsDomainCache, tlsDomainSet) != len(tlsDomainSet) {
		//
		certManager.HostPolicy = autocert.HostWhitelist(tlsDomainSet...)
		tlsDomainCache = tlsDomainSet
		hlog.Printf("info", "tls refresh %d, domains %s",
			len(tlsDomainSet), strings.Join(tlsDomainSet, ","))
	}

	if flush {
		if err := htoml.EncodeToFile(cfg, prefix+"/etc/config.toml"); err != nil {
			return err
		}
	}

	return nil
}

type compressWriter struct {
	http.ResponseWriter
	gzipWriter *gzip.Writer
	buf        *bytes.Buffer
	statusCode int
}

type respWriter struct {
	http.ResponseWriter

	statusCode int

	writeSize int
	writeBuff *bytes.Buffer

	gzipAccept bool
	gzipWriter *gzip.Writer
}

func (w *respWriter) Write(b []byte) (int, error) {

	w.writeSize += len(b)

	if w.writeBuff == nil {
		w.writeBuff = &bytes.Buffer{}
	}

	if w.Header().Get("Content-Encoding") != "" || !w.gzipAccept {
		return w.writeBuff.Write(b)
	}

	if w.gzipWriter == nil {
		w.gzipWriter = gzip.NewWriter(w.writeBuff)
	}

	return w.gzipWriter.Write(b)
}

func (w *respWriter) WriteHeader(statusCode int) {
	if statusCode > w.statusCode {
		w.statusCode = statusCode
	}
}

func (w *compressWriter) Write(b []byte) (int, error) {

	if w.gzipWriter == nil &&
		w.Header().Get("Content-Encoding") == "gzip" {
		return w.ResponseWriter.Write(b)
	}

	if w.buf == nil {
		w.buf = &bytes.Buffer{}
	}

	if w.gzipWriter == nil {
		w.gzipWriter = gzip.NewWriter(w.buf)
	}

	return w.gzipWriter.Write(b)
}

func (w *compressWriter) WriteHeader(statusCode int) {
	if statusCode > w.statusCode {
		w.statusCode = statusCode
	}
}

type httpRootHandler struct{}

func (it httpRootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if domain := cfg.Domain(r.Host); domain == nil {

		if module := cfg.Module(r.Host); module != nil {
			module.handler(&ServiceContext{Options: module.Options}, w, r)
		} else {

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			w.Write(builtin_404_HTML)
		}
	} else if domain.Domain.LetsencryptEnable {
		certManager.HTTPHandler(nil).ServeHTTP(w, r)
	} else {
		rootHandler(w, r)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {

	var (
		tn       = time.Now()
		urlPath  string
		hitRoute *DomainEntryRoute
		hw       = &respWriter{
			ResponseWriter: w,
		}
	)

	defer func() {
		lat := time.Since(tn)
		metricComplex.Add("Service", "RootHandler", 1, 0, lat)
		if hitRoute != nil {
			metricComplex.Add("Service", "RouteType:"+hitRoute.Type, 1, 0, lat)
		}
		if urlPath != "" {
			metricComplex.Add("HostService", r.Host+":"+urlPath, 1, 0, lat)
		}
		metricGauge.Add("Service", "RawSize", float64(hw.writeSize))
		if hw.writeBuff != nil {
			metricGauge.Add("Service", "CompSize", float64(hw.writeBuff.Len()))
		}
	}()

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		hw.gzipAccept = true
	}

	handler := func(w2 http.ResponseWriter, r *http.Request) *DomainEntryRoute {

		if domain := cfg.Domain(r.Host); domain != nil {

			//
			urlPath = filepath.Clean(r.URL.Path)
			if runtime.GOOS == "windows" {
				urlPath = strings.Replace(urlPath, "\\", "/", -1)
			}

			for _, route := range domain.Routes {

				if !strings.HasPrefix(urlPath, route.Path) {
					continue
				}

				switch route.Type {

				case "pod", "upstream":
					for _, u := range route.Urls {
						p := httputil.NewSingleHostReverseProxy(u)
						p.ServeHTTP(w2, r)
						return route
					}

				case "redirect":
					w2.Header().Set("Location", route.Urls[0].String())
					w2.WriteHeader(http.StatusFound)
					return route
				}
			}
		}

		w2.Header().Set("Content-Type", "text/html")
		w2.Write(builtin_404_HTML)
		w2.WriteHeader(404)

		return nil
	}

	hitRoute = handler(hw, r)

	w.Header().Del("X-Proxy")
	w.Header().Set("X-Proxy", "InnerStack/"+version)

	if hitRoute == nil {
		return
	}

	if hw.writeBuff != nil {

		if hw.gzipWriter != nil {
			hw.gzipWriter.Flush()
			hw.gzipWriter.Close()
			w.Header().Set("Content-Encoding", "gzip")
		}

		if hw.writeBuff.Len() > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(hw.writeBuff.Len()))
			if hw.statusCode > 0 {
				w.WriteHeader(hw.statusCode)
			}
			w.Write(hw.writeBuff.Bytes())
		}

	} else if uri := w.Header().Get("Location"); uri != "" &&
		w.Header().Get("Content-Type") == "" {
		if hw.statusCode >= 300 && hw.statusCode < 310 {
			w.WriteHeader(hw.statusCode)
		} else {
			w.WriteHeader(http.StatusFound)
		}
	} else if hw.statusCode > 0 {
		w.WriteHeader(hw.statusCode)
	}
}

func cmpHandler(fn http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			fn(w, r)
			return
		}

		cw := &compressWriter{
			ResponseWriter: w,
		}

		fn(cw, r)

		if cw.gzipWriter != nil {
			cw.gzipWriter.Flush()
			cw.gzipWriter.Close()
			w.Header().Set("Content-Encoding", "gzip")
		}

		if cw.buf != nil && cw.buf.Len() > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(cw.buf.Len()))
			if cw.statusCode > 0 {
				w.WriteHeader(cw.statusCode)
			}
			w.Write(cw.buf.Bytes())
		} else if uri := w.Header().Get("Location"); uri != "" &&
			w.Header().Get("Content-Type") == "" {
			if cw.statusCode >= 300 && cw.statusCode < 310 {
				w.WriteHeader(cw.statusCode)
			} else {
				w.WriteHeader(http.StatusFound)
			}
		} else if cw.statusCode > 0 {
			w.WriteHeader(cw.statusCode)
		}
	}
}

func httpHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("X-Proxy", "InnerStack/"+version)

	if domain := cfg.Domain(r.Host); domain != nil {
		//
		urlPath := filepath.Clean(r.URL.Path)
		if runtime.GOOS == "windows" {
			urlPath = strings.Replace(urlPath, "\\", "/", -1)
		}
		// urlPath = strings.Trim(urlPath, "/")

		for _, route := range domain.Routes {

			if !strings.HasPrefix(urlPath, route.Path) {
				continue
			}

			switch route.Type {

			case "pod", "upstream":
				for _, u := range route.Urls {
					p := httputil.NewSingleHostReverseProxy(u)
					p.ServeHTTP(w, r)
					return
				}

			case "redirect":
				w.Header().Set("Location", route.Urls[0].String())
				w.WriteHeader(http.StatusFound)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(builtin_404_HTML)
	w.WriteHeader(404)
}

// modules

type ServiceContext struct {
	Options map[string]string
}

func (it *ServiceContext) Option(name string) string {
	if it.Options != nil {
		return it.Options[name]
	}
	return ""
}

type ModuleHandler func(ctx *ServiceContext, w http.ResponseWriter, r *http.Request)

// module:DomainSale

func module_DomainSale_Handler(ctx *ServiceContext, w http.ResponseWriter, r *http.Request) {

	params := map[string]string{
		"domain_name":   r.Host,
		"contact_email": ctx.Option("contact_email"),
	}

	// data, _ := fs.ReadFile("modules/domain-sale.html")
	data, _ := tplrender.Render(module_DomainSale_HTML, params)

	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}
