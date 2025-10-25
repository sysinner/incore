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

package signals

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hooto/hlog4g/hlog"
)

const maxSignals = 128

var (
	mu sync.Mutex

	reg int = 0

	sigQueue = make(chan struct{}, 1)

	done = false

	shutdowns = []func(){}
)

func Add() {
	mu.Lock()
	defer mu.Unlock()

	if done {
		return
	}

	reg += 1
	if reg >= maxSignals {
		panic("too many signals")
	}
	hlog.Printf("info", "Signal Reg %d", reg)
}

func AddGo(start, shutdown func()) {

	mu.Lock()
	defer mu.Unlock()

	if start == nil || done {
		return
	}

	reg += 1
	if reg >= maxSignals {
		panic("too many signals")
	}

	if shutdown != nil {
		shutdowns = append(shutdowns, shutdown)
	}
	go start()
}

func Done() <-chan struct{} {
	return sigQueue
}

func DeferDone() {
	<-sigQueue
}

func Wait() {
	quit := make(chan os.Signal, 2)

	//
	signal.Notify(quit,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGKILL)
	sg := <-quit
	hlog.Printf("warn", "Signal %s ...", sg.String())

	mu.Lock()
	defer mu.Unlock()

	done = true

	if reg == 0 {
		return
	}

	for _, shutdown := range shutdowns {
		shutdown()
	}

	for i := 0; i < reg; i++ {
		sigQueue <- struct{}{}
	}

	sigQueue <- struct{}{}

	hlog.Printf("warn", "Signal %s ... Done", sg.String())
	hlog.Flush()
}
