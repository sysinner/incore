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

//go:generate protoc --proto_path=./ --go_opt=paths=source_relative --go_out=./ --go-grpc_out=./ app.proto base.proto cluster.proto mail.proto operator.proto pod.proto stats.proto
//go:generate protobuf_slice "*.proto"
//go:generate htoml-tag-fix ./

import (
	"fmt"
	"sync"
	"time"

	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
)

var (
	port_mu    sync.Mutex
	vol_mnt_mu sync.Mutex
)

const (
	RoleMaster = "master"
	RoleMember = "member"
)

const (
	ErrCodeServerError           = "ServerError"
	ErrCodeClientError           = "ClientError"
	ErrCodeAccessDenied          = "AccessDenied"
	ErrCodeUnauthorized          = "Unauthorized"
	ErrCodeBadArgument           = "BadArgument"
	ErrCodeObjectPending         = "ObjectPending"
	ErrCodeObjectNotFound        = "ObjectNotFound"
	ErrCodeObjectExists          = "ObjectAlreadyExists"
	ErrCodeObjectPathConflict    = "ObjectPathConflict"
	ErrCodeObjectVersionConflict = "ObjectVersionConflict" // test and set object
)

const (
	GeneralPhaseActive  = "Active"
	GeneralPhaseSuspend = "Suspend"
	GeneralPhaseOffline = "Offline"
)

func TimeNowMs() int64 {
	return (time.Now().UnixNano() / 1e6)
}

// Protocol defines network protocols supported for things like conatiner ports.
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
)

type GeneralObject struct {
	Kind  string           `json:"kind,omitempty" toml:"kind,omitempty"`
	Error *types.ErrorMeta `json:"error,omitempty" toml:"error,omitempty"`
}

type GeneralObjectList struct {
	Kind  string           `json:"kind,omitempty" toml:"kind,omitempty"`
	Error *types.ErrorMeta `json:"error,omitempty" toml:"error,omitempty"`
	Items []interface{}    `json:"items,omitempty" toml:"items,omitempty"`
}

// Port represents a network port in a single container
type Port struct {
	// Optional: If specified, this must be a DNS_LABEL.  Each named port
	// in a pod must have a unique name.
	Name string `json:"name,omitempty" toml:"name,omitempty"`
	// Optional: If specified, this must be a valid port number, 0 < x < 65536.
	Protocol Protocol `json:"protocol,omitempty" toml:"protocol,omitempty"`
	// Required: This must be a valid port number, 0 < x < 65536.
	BoxPort int `json:"box_port" toml:"box_port"`
	// Optional: If specified, this must be a valid port number, 0 < x < 65536.
	HostPort int `json:"host_port,omitempty" toml:"host_port,omitempty"`
	// Optional: What host IP to bind the external port to.
	HostIP string `json:"host_ip,omitempty" toml:"host_ip,omitempty"`
}

type Ports []Port

func (ls *Ports) Sync(item Port) (changed bool) {

	if item.BoxPort == 0 {
		return false
	}

	port_mu.Lock()
	defer port_mu.Unlock()

	for i, v := range *ls {

		if v.BoxPort != item.BoxPort {
			continue
		}

		if v.HostPort > 0 && v.HostPort != item.HostPort {
			(*ls)[i].HostPort = item.HostPort
			changed = true
		}

		if v.Name != item.Name {
			(*ls)[i].Name = item.Name
			changed = true
		}

		if v.Protocol != item.Protocol {
			(*ls)[i].Protocol = item.Protocol
			changed = true
		}

		return changed
	}

	*ls = append(*ls, item)

	return true
}

func (ls *Ports) Equal(items Ports) bool {

	if len(*ls) != len(items) {
		return false
	}

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.BoxPort != v2.BoxPort {
				continue
			}

			if v.HostPort != v2.HostPort ||
				v.Name != v2.Name ||
				v.Protocol != v2.Protocol {

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

type VolumeHostDir struct {
	HostDir string `json:"hostDir" toml:"hostDir"`
	// BoxPath    string `json:"boxPath,omitempty" toml:"boxPath,omitempty"`
	Path string `json:"path" toml:"path"`
}

// VolumePackage represents a volume that is pulled from lessos package service.
type VolumePackage struct {
	// Package Name form an identifier that is assumed to be completely unique
	Name string `json:"name" toml:"name"`
	// Package Version
	Version string `json:"version,omitempty" toml:"version,omitempty"`
	// Package Release
	Release string `json:"release,omitempty" toml:"release,omitempty"`
	// Distribution indicates the type of operating system.
	Dist string `json:"dist,omitempty" toml:"dist,omitempty"`
	// Architecture indicates the type of hardware.
	Arch string `json:"arch,omitempty" toml:"arch,omitempty"`

	//
	HostDir string `json:"hostDir,omitempty" toml:"hostDir,omitempty"`
}

// VolumeGitRepo represents a volume that is pulled from git when the pod is created.
type VolumeGitRepo struct {
	// Repository URL
	Repository string `json:"repository" toml:"repository"`
	// Commit hash, this is optional
	Revision string `json:"revision" toml:"revision"`
	//
	BoxPath string `json:"boxPath,omitempty" toml:"boxPath,omitempty"`
}

// VolumeMount describes a mounting of a Volume within a container.
type VolumeMount struct {
	// Required: This must match the Name of a Volume [above].
	Name string `json:"name,omitempty" toml:"name,omitempty"`
	// Optional: Defaults to false (read-write).
	ReadOnly bool `json:"readOnly,omitempty" toml:"readOnly,omitempty"`
	// Required.
	MountPath string `json:"mountPath" toml:"mountPath"`
	// //
	HostDir string `json:"hostDir,omitempty" toml:"hostDir,omitempty"`
}

type VolumeMounts []VolumeMount

func (ls *VolumeMounts) Sync(item VolumeMount) bool {

	for i, v := range *ls {

		if v.MountPath != item.MountPath {
			continue
		}

		if v.HostDir != item.HostDir ||
			v.ReadOnly != item.ReadOnly {

			(*ls)[i].HostDir = item.HostDir
			(*ls)[i].ReadOnly = item.ReadOnly

			return true
		}

		return false
	}

	*ls = append(*ls, item)

	return true
}

func (ls *VolumeMounts) Equal(items VolumeMounts) bool {

	if len(*ls) != len(items) {
		return false
	}

	for _, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.MountPath == v2.MountPath {

				if v.ReadOnly != v2.ReadOnly ||
					v.HostDir != v2.HostDir {
					return false
				}

				hit = true
				break
			}
		}

		if !hit {
			return false
		}
	}

	return true
}

func (ls *VolumeMounts) DiffSync(items VolumeMounts) {

	vol_mnt_mu.Lock()
	defer vol_mnt_mu.Unlock()

	for i, v := range *ls {

		hit := false

		for _, v2 := range items {

			if v.MountPath == v2.MountPath {
				hit = true
				break
			}
		}

		if !hit {
			*ls = append((*ls)[:i], (*ls)[i+1:]...)
		}
	}

	for _, v2 := range items {
		ls.Sync(v2)
	}
}

// EnvVar represents an environment variable present in a Box.
type EnvVar struct {
	Name  string `json:"name" toml:"name"`
	Value string `json:"value,omitempty" toml:"value,omitempty"`
}

func ObjPrint(name string, v interface{}) {
	js, _ := json.Encode(v, "  ")
	fmt.Println("\n", name, string(js))
}

func ObjSprint(v interface{}, idx string) string {
	js, _ := json.Encode(v, idx)
	return string(js)
}
