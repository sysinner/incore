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

package losapi

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// default: 127.0.0.1:9529
type HostNodeAddress string

func (addr HostNodeAddress) String() string {
	return string(addr)
}

func (addr HostNodeAddress) Valid() bool {

	if addr.Port() < 1 {
		return false
	}

	if v := net.ParseIP(addr.IP()); v == nil || len(v) != 16 {
		return false
	}

	return true
}

func (addr HostNodeAddress) IP() string {

	if pos := strings.LastIndex(string(addr), ":"); pos > 0 {
		return string(addr)[:pos]
	}

	return string(addr)
}

func (addr HostNodeAddress) Port() uint16 {

	if pos := strings.LastIndex(string(addr), ":"); pos > 0 {
		port, _ := strconv.Atoi(string(addr)[pos+1:])
		return uint16(port)
	}

	return 0
}

func (addr *HostNodeAddress) SetIP(ip string) error {

	if addr.Port() > 0 {
		*addr = HostNodeAddress(fmt.Sprintf("%s:%d", ip, addr.Port()))
	} else {
		*addr = HostNodeAddress(ip)
	}

	return nil
}

func (addr *HostNodeAddress) SetPort(port uint16) error {

	if (*addr).IP() != "" {
		*addr = HostNodeAddress(fmt.Sprintf("%s:%d", addr.IP(), port))
	} else {
		*addr = HostNodeAddress(fmt.Sprintf(":%d", port))
	}

	return nil
}
