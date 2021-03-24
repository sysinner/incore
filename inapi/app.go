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

package inapi

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/lessos/lessgo/types"
)

var (
	appOpMu             sync.RWMutex
	appOpRefMu          sync.RWMutex
	appSpecCfgNameReg   = regexp.MustCompile("^[a-z]{1}[a-z0-9_]{1,30}$")
	AppIdRe2            = regexp.MustCompile("^[a-f0-9]{16,24}$")
	AppSpecIdReg        = regexp.MustCompile("^[a-z]{1}[a-z0-9_-]{2,39}$")
	AppSpecVcsGitUrlReg = regexp.MustCompile(`^(https?:\/\/)([\w\-_\.\/]+)(\.git)$`)
	AppSpecVcsDirReg    = regexp.MustCompile(`^[a-zA-Z0-9\.\/\-_]{1,50}$`)
	AppSpecUrlNameRE    = regexp.MustCompile("^[a-z]{1}[a-z0-9_]{1,30}$")
	AppSpecImageNameRE  = regexp.MustCompile("^[a-z0-9\\-\\_]{1,50}\\/[a-z0-9\\-\\_]{1,50}\\:[a-z0-9\\.\\-\\_]{1,50}$")
)

type AppPhase string

const (
	AppPending   AppPhase = "Pending"
	AppRunning   AppPhase = "Running"
	AppSucceeded AppPhase = "Succeeded"
	AppFailed    AppPhase = "Failed"
)

type AppInstance struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta `json:"meta,omitempty" toml:"meta,omitempty"`

	// Spec defines the behavior of a app.
	Spec AppSpec `json:"spec,omitempty" toml:"spec,omitempty"`

	//
	Operate AppOperate `json:"operate,omitempty" toml:"operate,omitempty"`

	// Status represents the current information about a app. This data may not be up
	// to date.
	Status *AppStatus `json:"status,omitempty" toml:"status,omitempty"`
}

type AppInstanceList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          AppInstances `json:"items,omitempty" toml:"items,omitempty"`
}

type AppInstances []*AppInstance

func (ls *AppInstances) Sync(app *AppInstance) {

	for i, v := range *ls {

		if v.Meta.ID == app.Meta.ID {
			(*ls)[i] = app
			return
		}
	}

	*ls = append(*ls, app)
}

func (ls *AppInstances) ExecutorSync(executor Executor, app_id string) {

	for i, v := range *ls {

		if v.Meta.ID == app_id {
			(*ls)[i].Spec.Executors.Sync(executor)
			break
		}
	}
}

func (ls *AppInstances) SpecExpDeployStateless() bool {
	n := 0
	for _, v := range *ls {
		if v.Spec.ExpDeploy == nil {
			v.Spec.ExpDeploy = &AppSpecExpDeployRequirements{}
		}
		if v.Spec.ExpDeploy.Stateless() {
			n += 1
		}
	}
	if n > 0 && n == len(*ls) {
		return true
	}
	return false

}

func (ls *AppInstances) SpecExpDeployFailoverLimits() (delaySeconds, numMax, rateMax int32) {
	for _, v := range *ls {
		if v.Spec.ExpDeploy == nil {
			v.Spec.ExpDeploy = &AppSpecExpDeployRequirements{}
		}
		if v.Spec.ExpDeploy.FailoverTime > delaySeconds {
			delaySeconds = v.Spec.ExpDeploy.FailoverTime
		}
		if v.Spec.ExpDeploy.FailoverNumMax > numMax {
			numMax = v.Spec.ExpDeploy.FailoverNumMax
		}
		if v.Spec.ExpDeploy.FailoverRateMax > rateMax {
			rateMax = v.Spec.ExpDeploy.FailoverRateMax
		}
	}
	return
}

func (ls *AppInstances) SpecExpDeployFailoverEnable() bool {
	n := 0
	for _, v := range *ls {
		if v.Spec.ExpDeploy == nil {
			v.Spec.ExpDeploy = &AppSpecExpDeployRequirements{}
		}
		if v.Spec.ExpDeploy.FailoverEnable() {
			n += 1
		}
	}
	if n > 0 && n == len(*ls) {
		return true
	}
	return false
}

func (ls *AppInstances) NetworkModeHost() bool {
	hostN := 0
	for _, v := range *ls {
		if v.Spec.ExpDeploy == nil {
			v.Spec.ExpDeploy = &AppSpecExpDeployRequirements{}
		}
		if v.Spec.ExpDeploy.NetworkMode == AppSpecExpDeployNetworkModeHost {
			hostN += 1
		}
	}
	if hostN > 0 && hostN == len(*ls) {
		return true
	}
	return false
}

func (it *AppSpecDepend) Valid() error {
	if !AppSpecIdReg.MatchString(it.Id) {
		return errors.New("Invalid AppSpecDepend.ID")
	}
	return nil
}

//
type AppSpec struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Meta           types.InnerObjectMeta         `json:"meta" toml:"meta"`
	LastVersion    string                        `json:"last_version,omitempty" toml:"last_version,omitempty"`
	Roles          types.ArrayUint32             `json:"roles,omitempty" toml:"roles,omitempty"`
	Vendor         string                        `json:"vendor,omitempty" toml:"vendor,omitempty"`
	RuntimeImages  []string                      `json:"runtime_images,omitempty" toml:"runtime_images,omitempty"`
	Depends        []*AppSpecDepend              `json:"depends,omitempty" toml:"depends,omitempty"`
	DepRemotes     []*AppSpecDepend              `json:"dep_remotes,omitempty" toml:"dep_remotes,omitempty"`
	Packages       AppPackages                   `json:"packages,omitempty" toml:"packages,omitempty"`
	VcsRepos       VcsRepoItems                  `json:"vcs_repos,omitempty" toml:"vcs_repos,omitempty"`
	Executors      Executors                     `json:"executors,omitempty" toml:"executors,omitempty"`
	VolumeMounts   AppVolumeMounts               `json:"volume_mounts,omitempty" toml:"volume_mounts,omitempty"`
	ServicePorts   ServicePorts                  `json:"service_ports,omitempty" toml:"service_ports,omitempty"`
	Configurator   *AppConfigurator              `json:"configurator,omitempty" toml:"configurator,omitempty"`
	ExpRes         *AppSpecResRequirements       `json:"exp_res,omitempty" toml:"exp_res,omitempty"`
	ExpDeploy      *AppSpecExpDeployRequirements `json:"exp_deploy,omitempty" toml:"exp_deploy,omitempty"`
	Comment        string                        `json:"comment,omitempty" toml:"comment,omitempty"`
	TypeTags       []string                      `json:"type_tags,omitempty" toml:"type_tags,omitempty"`
	Description    string                        `json:"description,omitempty" toml:"description,omitempty"`
	Urls           []*AppSpecUrlEntry            `json:"urls,omitempty" toml:"urls,omitempty"`
}

func appSpecVersioUpgrade(v string) string {
	return NewAppSpecVersion(v).PrefixString()
}

type AppSpecDependPrev AppSpecDepend

func (it *AppSpecDepend) UnmarshalJSON(b []byte) error {

	var it2 AppSpecDependPrev
	if err := json.Unmarshal(b, &it2); err != nil {
		return err
	}

	it2.Version = appSpecVersioUpgrade(it2.Version)

	*it = AppSpecDepend(it2)

	return nil
}

type AppSpecPrev AppSpec

func (it *AppSpec) Fix() *AppSpec {
	if len(it.RuntimeImages) == 0 {
		it.RuntimeImages = []string{
			"sysinner/innerstack-g3:el8",
			"sysinner/innerstack-g2:el7",
		}
	}
	return it
}

func (it *AppSpec) UnmarshalJSON(b []byte) error {

	var it2 AppSpecPrev
	if err := json.Unmarshal(b, &it2); err != nil {
		return err
	}

	it2.Meta.Version = appSpecVersioUpgrade(it2.Meta.Version)
	it2.LastVersion = appSpecVersioUpgrade(it2.LastVersion)

	*it = AppSpec(it2)
	it.Fix()

	return nil
}

type AppSpecUrlEntry struct {
	Name string `json:"name" toml:"name"`
	Url  string `json:"url,omitempty" toml:"url,omitempty"`
}

type AppSpecTagEntry struct {
	Name  string `json:"name" toml:"name"`
	Value string `json:"value" toml:"value"`
}

var (
	AppSpecTypeTagDicts = []*AppSpecTagEntry{
		{Name: "devops", Value: "DevOps"},         // Development and Operations
		{Name: "enterprise", Value: "Enterprise"}, // Enterprise Applications
		{Name: "database", Value: "Database"},
		{Name: "storage", Value: "Storage"},
		{Name: "runtime", Value: "Runtime"},
		{Name: "bigdata", Value: "BigData"},
		{Name: "net", Value: "Network"},
		{Name: "security", Value: "Security"},
		{Name: "ai", Value: "AI"},
		{Name: "iot", Value: "IoT"},
	}
	appSpecTypeTagSets = map[string]bool{}
)

func init() {
	for _, v := range AppSpecTypeTagDicts {
		appSpecTypeTagSets[v.Name] = true
	}
}

func (it *AppSpec) Reset() *AppSpec {
	tTags := []string{}
	for _, v := range it.TypeTags {
		v = strings.ToLower(strings.TrimSpace(v))
		if _, ok := appSpecTypeTagSets[v]; ok &&
			!ArrayStringHas(tTags, v) {
			tTags = append(tTags, v)
		}
	}
	it.TypeTags = tTags
	return it
}

type AppSpecResRequirements struct {
	CpuMin int32 `json:"cpu_min,omitempty" toml:"cpu_min,omitempty"`
	MemMin int32 `json:"mem_min,omitempty" toml:"mem_min,omitempty"`
	VolMin int32 `json:"vol_min,omitempty" toml:"vol_min,omitempty"`
}

const (
	AppSpecExpDeployRepNumMin         int32 = 1 // default
	AppSpecExpDeployRepNumMax         int32 = 32
	AppSpecExpDeploySysStateful       int32 = 1 // default
	AppSpecExpDeploySysStateless      int32 = 2
	AppSpecExpDeployNetworkModeBridge int32 = 1 // default
	AppSpecExpDeployNetworkModeHost   int32 = 2
)

type AppSpecExpDeployRequirements struct {
	RepMin   int32 `json:"rep_min,omitempty" toml:"rep_min,omitempty"`
	RepMax   int32 `json:"rep_max,omitempty" toml:"rep_max,omitempty"`
	SysState int32 `json:"sys_state,omitempty" toml:"sys_state,omitempty"`
	// High-Availability
	FailoverTime    int32 `json:"failover_time,omitempty" toml:"failover_time,omitempty"`         // in seconds
	FailoverNumMax  int32 `json:"failover_num_max,omitempty" toml:"failover_num_max,omitempty"`   // [0, RepMax)
	FailoverRateMax int32 `json:"failover_rate_max,omitempty" toml:"failover_rate_max,omitempty"` // [0, 100) in %
	NetworkMode     int32 `json:"network_mode" toml:"network_mode"`
}

func (it *AppSpecExpDeployRequirements) FailoverEnable() bool {

	if it.FailoverTime < HealthFailoverActiveTimeMin {
		return false
	}

	if it.FailoverNumMax < 1 && it.FailoverRateMax < 1 {
		return false
	}

	if it.FailoverRateMax >= 50 {
		return false
	}

	return true
}

func (it *AppSpecExpDeployRequirements) Stateless() bool {
	return it.SysState == AppSpecExpDeploySysStateless
}

type AppSpecList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []*AppSpec         `json:"items,omitempty" toml:"items,omitempty"`
	TypeTagDicts   []*AppSpecTagEntry `json:"type_tag_dicts,omitempty" toml:"type_tag_dicts,omitempty"`
}

type AppSpecVersionEntry struct {
	Version string `json:"version" toml:"version"`
	Created uint64 `json:"created" toml:"created"`
	Comment string `json:"comment" toml:"comment"`
}

type AppSpecVersionList struct {
	types.TypeMeta `json:",inline" toml:",inline"`
	Items          []AppSpecVersionEntry `json:"items,omitempty" toml:"items,omitempty"`
}

type AppPackages []VolumePackage

func (ls *AppPackages) Insert(vol VolumePackage) {

	for i, v := range *ls {

		if v.Name == vol.Name {
			(*ls)[i] = vol
			return
		}
	}

	*ls = append(*ls, vol)
}

func (ls *AppPackages) Remove(name string) {

	for i, v := range *ls {

		if v.Name == name {
			*ls = append((*ls)[0:i], (*ls)[i+1:]...)
			break
		}
	}
}

//
type AppVolumeMount struct {
	Name     string `json:"name" toml:"name"`
	Path     string `json:"path" toml:"path"`
	BoxBound string `json:"box_bound,omitempty" toml:"box_bound,omitempty"`
}

type AppVolumeMounts []AppVolumeMount

//
type AppConfigurator struct {
	Name   types.NameIdentifier `json:"name" toml:"name"`
	Fields AppConfigFields      `json:"fields,omitempty" toml:"fields,omitempty"`
}

func (it *AppConfigurator) Valid() error {

	if err := it.Name.Valid(); err != nil {
		return errors.New("invalid name : " + err.Error())
	}

	name := strings.ToLower(it.Name.String())
	if !strings.HasPrefix(name, "cfg/") {
		name = "cfg/" + name
	}
	it.Name = types.NameIdentifier(name)

	return nil
}

const (
	AppConfigFieldTypeString uint16 = 1
	AppConfigFieldTypeSelect uint16 = 2

	AppConfigFieldTypeText               uint16 = 300
	AppConfigFieldTypeTextJSON           uint16 = 301
	AppConfigFieldTypeTextTOML           uint16 = 302
	AppConfigFieldTypeTextYAML           uint16 = 303
	AppConfigFieldTypeTextINI            uint16 = 304
	AppConfigFieldTypeTextJavaProperties uint16 = 305

	AppConfigFieldTypeAuthCert uint16 = 900

	AppConfigFieldAutoFillDefaultValue = "defval"
	AppConfigFieldAutoFillHexString_32 = "hexstr_32"
	AppConfigFieldAutoFillBase64_48    = "base64_48"
)

func AppConfigFieldAutoFillValid(v string) bool {

	switch v {

	case AppConfigFieldAutoFillDefaultValue,
		AppConfigFieldAutoFillHexString_32,
		AppConfigFieldAutoFillBase64_48:

	default:
		return false
	}

	return true
}

type AppConfigField struct {
	Name        string        `json:"name" toml:"name"`
	Title       string        `json:"title,omitempty" toml:"title,omitempty"`
	Prompt      string        `json:"prompt,omitempty" toml:"prompt,omitempty"`
	Type        uint16        `json:"type,omitempty" toml:"type,omitempty"`
	Default     string        `json:"default,omitempty" toml:"default,omitempty"`
	AutoFill    string        `json:"auto_fill,omitempty" toml:"auto_fill,omitempty"`
	Enums       types.Labels  `json:"enums,omitempty" toml:"enums,omitempty"`
	Validates   types.KvPairs `json:"validates,omitempty" toml:"validates,omitempty"`
	Description string        `json:"description,omitempty" toml:"description,omitempty"`
}

type AppConfigFields []*AppConfigField

type AppConfigDepend struct {
	Name  types.NameIdentifier `json:"name" toml:"name"`
	Title string               `json:"title,omitempty" toml:"title,omitempty"`
}

type AppConfigDepends []*AppConfigDepend

func (ls *AppConfigFields) Sync(item AppConfigField) {

	appOpMu.Lock()
	defer appOpMu.Unlock()

	if !appSpecCfgNameReg.MatchString(item.Name) {
		return
	}

	for i, v := range *ls {

		if v.Name == item.Name {
			(*ls)[i] = &item
			return
		}
	}

	*ls = append(*ls, &item)
}

func (ls *AppConfigFields) Del(name string) {

	appOpMu.Lock()
	defer appOpMu.Unlock()

	for i, v := range *ls {

		if v.Name == name {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

type AppConfigFieldHelper interface {
	Valid(field *AppConfigField) error
}

type AppConfigFieldTypeCA struct {
}

func (it *AppConfigFieldTypeCA) Valid(field *AppConfigField) error {
	return nil
}

//
type AppOperate struct {
	Action        uint32            `json:"action,omitempty" toml:"action,omitempty"`
	Zone          string            `json:"zone,omitempty" toml:"zone,omitempty"`
	PodId         string            `json:"pod_id,omitempty" toml:"pod_id,omitempty"`
	Options       AppOptions        `json:"options,omitempty" toml:"options,omitempty"`
	Services      []*AppServicePort `json:"services,omitempty" toml:"services,omitempty"`
	BindServices  []*AppServicePort `json:"bind_services,omitempty" toml:"bind_services,omitempty"`
	ResBoundRoles types.ArrayUint32 `json:"res_bound_roles,omitempty" toml:"res_bound_roles,omitempty"`
}

func (it *AppOperate) Service(spec string, port uint32, pod_id string) *AppServicePort {
	if len(it.Services) > 0 {
		return AppServicePortSliceGet(it.Services, port, pod_id)
	}
	return nil
}

type AppOptionField struct {
	Type  uint16 `json:"type,omitempty" toml:"type,omitempty"`
	Name  string `json:"name" toml:"name"`
	Value string `json:"value" toml:"value"`
}

type AppOption struct {
	Name    types.NameIdentifier `json:"name" toml:"name"`
	Items   []*AppOptionField    `json:"items,omitempty" toml:"items,omitempty"`
	Subs    types.ArrayString    `json:"subs,omitempty" toml:"subs,omitempty"`
	Ref     *AppOptionRef        `json:"ref,omitempty" toml:"ref,omitempty"`
	User    string               `json:"user,omitempty" toml:"user,omitempty"`
	Updated types.MetaTime       `json:"updated,omitempty" toml:"updated,omitempty"`
}

func (it *AppOption) Field(name string) *AppOptionField {
	for _, v := range it.Items {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (it *AppOption) ValueOK(name string) (types.Bytex, bool) {
	for _, v := range it.Items {
		if v.Name == name {
			return types.Bytex(v.Value), true
		}
	}
	return types.Bytex{}, false
}

func (it *AppOption) Value(name string) types.Bytex {
	v, _ := it.ValueOK(name)
	return v
}

type AppOptions []*AppOption

func (ls *AppOptions) Get(name string) *AppOption {

	appOpMu.RLock()
	defer appOpMu.RUnlock()

	for _, v := range *ls {

		if v.Name == types.NameIdentifier(name) {
			return v
		}
	}

	return nil
}

func (ls *AppOptions) Set(item AppOption) (changed bool) {

	appOpMu.Lock()
	defer appOpMu.Unlock()

	for i, v := range *ls {

		if v.Name == item.Name {

			if item.Ref != nil && v.Ref != nil &&
				item.Ref.SpecId == v.Ref.SpecId &&
				item.Ref.AppId != v.Ref.AppId {
				continue
			}

			if item.Updated > v.Updated {
				(*ls)[i], changed = &item, true
			}

			return changed
		}
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptions) Sync(item AppOption) (changed bool) {

	appOpMu.Lock()
	defer appOpMu.Unlock()

	for _, prev := range *ls {

		if prev.Name != item.Name {
			continue
		}

		if item.Ref != nil && prev.Ref != nil &&
			item.Ref.SpecId == prev.Ref.SpecId &&
			item.Ref.AppId != prev.Ref.AppId {
			continue
		}

		if prev.Updated != item.Updated {
			prev.Updated = item.Updated
			changed = true
		}

		if !ValueEqual(prev.Items, item.Items) {
			prev.Items = item.Items
			changed = true
		}

		if !prev.Subs.Equal(item.Subs) {
			prev.Subs = item.Subs
			changed = true
		}

		if (prev.Ref == nil && item.Ref != nil) ||
			(prev.Ref != nil && !prev.Ref.Equal(item.Ref)) {
			prev.Ref = item.Ref
			changed = true
		}

		return changed
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptions) Del(name string) {

	appOpMu.Lock()
	defer appOpMu.Unlock()

	for i, prev := range *ls {

		if prev.Name == types.NameIdentifier(name) {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

type AppOptionRef struct {
	SpecId  string       `json:"spec_id" toml:"spec_id"`
	AppId   string       `json:"app_id" toml:"app_id"`
	PodId   string       `json:"pod_id" toml:"pod_id"`
	Ports   ServicePorts `json:"ports,omitempty" toml:"ports,omitempty"`
	Updated int64        `json:"updated,omitempty" toml:"updated,omitempty"`
}

func (it *AppOptionRef) Equal(item *AppOptionRef) bool {

	if it == nil && item != nil {
		return false
	}

	if it != nil {

		if item == nil {
			return true
		}

		if it.AppId != item.AppId ||
			it.PodId != item.PodId ||
			!it.Ports.Equal(item.Ports) {
			return false
		}
	}

	return true
}

type AppOptionRefs []*AppOptionRef

func (ls *AppOptionRefs) Get(app_id string) *AppOptionRef {

	appOpRefMu.RLock()
	defer appOpRefMu.RUnlock()

	for _, v := range *ls {

		if v.AppId == app_id {
			return v
		}
	}

	return nil
}

func (ls *AppOptionRefs) Sync(item AppOptionRef) (changed bool) {

	appOpRefMu.Lock()
	defer appOpRefMu.Unlock()

	for _, prev := range *ls {

		if prev.AppId != item.AppId {
			continue
		}

		if prev.PodId != item.PodId {
			prev.PodId = item.PodId
			changed = true
		}

		if !prev.Ports.Equal(item.Ports) {
			prev.Ports = item.Ports
			changed = true
		}

		return changed
	}

	*ls = append(*ls, &item)

	return true
}

func (ls *AppOptionRefs) Del(app_id string) {

	appOpRefMu.Lock()
	defer appOpRefMu.Unlock()

	for i, prev := range *ls {

		if prev.AppId == app_id {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
			return
		}
	}
}

func (ls *AppOptionRefs) Equal(items AppOptionRefs) bool {

	appOpRefMu.Lock()
	defer appOpRefMu.Unlock()

	if len(*ls) != len(items) {
		return false
	}

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.AppId != v2.AppId {
				continue
			}

			if v.PodId != v2.PodId {
				return false
			}

			if !v.Ports.Equal(v2.Ports) {
				return false
			}

			hit = true
			break
		}

		if !hit {
			return false
		}
	}

	return true
}

type AppConfigSet struct {
	Id         string                           `json:"id" toml:"id"`
	SpecId     string                           `json:"spec_id" toml:"spec_id"`
	Option     AppOption                        `json:"option" toml:"option"`
	DepRemotes []*AppConfigSetAppSpecRemoteBind `json:"dep_remotes,omitempty" toml:"dep_remotes,omitempty"`
}

type AppConfigSetAppSpecRemoteBind struct {
	SpecId  string   `json:"spec_id" toml:"spec_id"`
	AppId   string   `json:"app_id" toml:"app_id"`
	Configs []string `json:"configs" toml:"configs"`
	Delete  bool     `json:"delete,omitempty" toml:"delete,omitempty"`
}

type AppStatus struct {
	Phase AppPhase `json:"phase,omitempty" toml:"phase,omitempty"`
}
